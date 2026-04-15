//! SpdzPreprocessing adapter backed by the PCG.
//!
//! Triples come from the PCG's OLE expansion. Shared randoms, bits, and input
//! masks use the same trusted-dealer construction as `DummyPreprocessing`
//! (not on the critical path for demonstrating PCG; easy to replace later
//! with dedicated correlation generators).

use pcg_core::pcg::{PcgParams, PcgSeed, Role};
use pcg_protocols::OleProtocol;
use pcg_core::ring_lpn_pcg::{RingLpnPcgParams, RingLpnPcgSeed};
use pcg_core::triples::{ole_to_beaver_triples, BeaverTripleShare};
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use spdz_core::preprocessing::SpdzPreprocessing;
use spdz_core::SpdzPrimeFieldShare;

/// Triples per expansion batch. Each expansion produces N=2^log_n OLEs →
/// N/2 triples.
const DEFAULT_LOG_N: usize = 16; // 2^16 = 65536 OLEs per batch → 32768 triples

pub struct PcgPreprocessing<F: PrimeField + ark_ff::FftField> {
    party_id: usize,
    role: Role,
    mac_key_share: F,
    /// Only populated in `new_insecure` mode; in protocol mode we just hold the
    /// share. Used by `test_pcg_preprocessing_mac_key` to sanity-check.
    pub(crate) mac_key: F,
    rng: ChaCha20Rng,

    // Current batch of triples pulled from the most-recent expansion
    triple_buf: Vec<BeaverTripleShare<F>>,

    // Non-triple material (trusted-dealer style for MVP)
    random_buf: Vec<SpdzPrimeFieldShare<F>>,
    bit_buf: Vec<SpdzPrimeFieldShare<F>>,
    input_mask_buf: Vec<(F, SpdzPrimeFieldShare<F>)>,
    counter_mask_buf: Vec<SpdzPrimeFieldShare<F>>,

    params: PcgParams,
    batch_counter: u64,
    shared_seed: u64,

    /// Real 2-party protocol for computing c shares. If present, `refill_triples`
    /// uses it (Phase 2a+ mode). If None, uses the legacy trusted-dealer seed
    /// derivation from `shared_seed` (insecure MVP mode).
    protocol: Option<Box<dyn OleProtocol<F>>>,

    /// This party's private RNG for generating its own `a` polynomial each
    /// batch in protocol mode. Only used when `protocol.is_some()`.
    private_poly_rng: ChaCha20Rng,

    /// Ring-LPN PCG parameters. When present, `refill_triples` uses the
    /// sub-linear Ring-LPN construction (Phase 2b). Trusted-dealer seeds
    /// for each batch are derived from `shared_seed + batch_counter`.
    /// Mutually exclusive with `protocol`.
    ring_lpn_params: Option<RingLpnPcgParams<F>>,
    /// Sparsity parameter for Ring-LPN mode.
    ring_lpn_t: usize,
}

unsafe impl<F: PrimeField + ark_ff::FftField> Send for PcgPreprocessing<F> {}

impl<F: PrimeField + ark_ff::FftField> PcgPreprocessing<F> {
    /// Create a PCG-backed preprocessing source for MVP testing.
    ///
    /// Both parties should call this with the SAME `shared_seed` but different
    /// `party_id`. The seed drives both the trusted-dealer dummy correlations
    /// (randoms/bits/masks) and the PCG seed pair generation.
    pub fn new_insecure(party_id: usize, shared_seed: u64, log_n: usize) -> Self {
        assert!(party_id == 0 || party_id == 1);
        let role = if party_id == 0 { Role::P0 } else { Role::P1 };
        let params = PcgParams { log_n };

        // Derive a MAC key from the shared seed (same on both parties).
        let mut seed_rng = ChaCha20Rng::seed_from_u64(shared_seed);
        let mac_key = F::rand(&mut seed_rng);
        // Split MAC key additively.
        let mk0 = F::rand(&mut seed_rng);
        let mk1 = mac_key - mk0;
        let mac_key_share = if party_id == 0 { mk0 } else { mk1 };

        // Per-party RNG: includes the party id so each party's private ops differ.
        let rng = ChaCha20Rng::seed_from_u64(shared_seed.wrapping_add(party_id as u64));

        Self {
            party_id,
            role,
            mac_key_share,
            mac_key,
            rng,
            triple_buf: Vec::new(),
            random_buf: Vec::new(),
            bit_buf: Vec::new(),
            input_mask_buf: Vec::new(),
            counter_mask_buf: Vec::new(),
            params,
            batch_counter: 0,
            shared_seed,
            protocol: None,
            private_poly_rng: ChaCha20Rng::seed_from_u64(shared_seed ^ 0xBEEF),
            ring_lpn_params: None,
            ring_lpn_t: 0,
        }
    }

    /// Phase 2a constructor: uses a real 2-party OLE protocol for triple
    /// generation. Each party calls this with its own `private_seed` (unknown
    /// to the peer) plus a `protocol` that coordinates with the peer.
    ///
    /// `shared_seed` is only used for the non-triple correlations (shared
    /// randoms, bits, input masks), which still use the trusted-dealer MVP
    /// in this phase.
    pub fn new_with_protocol(
        party_id: usize,
        private_seed: u64,
        shared_seed: u64,
        log_n: usize,
        protocol: Box<dyn OleProtocol<F>>,
    ) -> Self {
        assert!(party_id == 0 || party_id == 1);
        let role = if party_id == 0 { Role::P0 } else { Role::P1 };
        let params = PcgParams { log_n };

        // MAC key shares still come from shared_seed (non-triple path).
        let mut seed_rng = ChaCha20Rng::seed_from_u64(shared_seed);
        let mac_key = F::rand(&mut seed_rng);
        let mk0 = F::rand(&mut seed_rng);
        let mk1 = mac_key - mk0;
        let mac_key_share = if party_id == 0 { mk0 } else { mk1 };

        let rng = ChaCha20Rng::seed_from_u64(shared_seed.wrapping_add(party_id as u64));

        Self {
            party_id,
            role,
            mac_key_share,
            mac_key,
            rng,
            triple_buf: Vec::new(),
            random_buf: Vec::new(),
            bit_buf: Vec::new(),
            input_mask_buf: Vec::new(),
            counter_mask_buf: Vec::new(),
            params,
            batch_counter: 0,
            shared_seed,
            protocol: Some(protocol),
            private_poly_rng: ChaCha20Rng::seed_from_u64(private_seed),
            ring_lpn_params: None,
            ring_lpn_t: 0,
        }
    }

    /// Phase 2b.2d constructor: sub-linear Ring-LPN PCG with trusted-dealer
    /// seed generation for each batch.
    ///
    /// Both parties call with the SAME `shared_seed`, `log_n`, `t`, and
    /// `a_seed`. The Ring-LPN public polynomial `a` is derived from `a_seed`;
    /// each batch's dealer seed is `shared_seed + batch_counter · 0xA11CE`.
    ///
    /// This is INSECURE (shared dealer seed → either party can recompute the
    /// other's sparse polys). Phase 2b.2e replaces the dealer with real
    /// 2-party DMPF key gen via OT.
    pub fn new_ring_lpn_insecure(
        party_id: usize,
        shared_seed: u64,
        log_n: u32,
        t: usize,
        a_seed: u64,
    ) -> Self {
        assert!(party_id == 0 || party_id == 1);
        let role = if party_id == 0 { Role::P0 } else { Role::P1 };
        let params = PcgParams {
            log_n: log_n as usize,
        };

        // MAC key shares from shared_seed (same trusted-dealer pattern as before).
        let mut seed_rng = ChaCha20Rng::seed_from_u64(shared_seed);
        let mac_key = F::rand(&mut seed_rng);
        let mk0 = F::rand(&mut seed_rng);
        let mk1 = mac_key - mk0;
        let mac_key_share = if party_id == 0 { mk0 } else { mk1 };

        let rng = ChaCha20Rng::seed_from_u64(shared_seed.wrapping_add(party_id as u64));

        let ring_lpn_params = RingLpnPcgParams::<F>::new(log_n, t, a_seed);

        Self {
            party_id,
            role,
            mac_key_share,
            mac_key,
            rng,
            triple_buf: Vec::new(),
            random_buf: Vec::new(),
            bit_buf: Vec::new(),
            input_mask_buf: Vec::new(),
            counter_mask_buf: Vec::new(),
            params,
            batch_counter: 0,
            shared_seed,
            protocol: None,
            private_poly_rng: ChaCha20Rng::seed_from_u64(shared_seed ^ 0xDEAD),
            ring_lpn_params: Some(ring_lpn_params),
            ring_lpn_t: t,
        }
    }

    fn refill_triples(&mut self) {
        if self.ring_lpn_params.is_some() {
            self.refill_triples_ring_lpn();
        } else if self.protocol.is_some() {
            self.refill_triples_via_protocol();
        } else {
            self.refill_triples_trusted_dealer();
        }
    }

    fn refill_triples_via_protocol(&mut self) {
        let n = self.params.n();
        // Generate my own private `a` polynomial from the private RNG.
        let my_a: Vec<F> = (0..n).map(|_| F::rand(&mut self.private_poly_rng)).collect();

        // Call the protocol to get my share of c = a_0 * a_1 (cyclic).
        let log_n = self.params.log_n;
        let protocol = self.protocol.as_mut().expect("protocol must be set");
        let my_c = protocol
            .cyclic_conv_share(&my_a, log_n)
            .expect("OLE protocol failed");

        // Assemble a PcgSeed with my own (a, c) and expand to OLE correlations.
        let seed = PcgSeed::<F> {
            role: self.role,
            params: self.params.clone(),
            a: my_a,
            c: my_c,
        };
        let ole = seed.expand();
        let triples = ole_to_beaver_triples(&ole, self.role);
        self.triple_buf = triples;
        self.batch_counter += 1;
    }

    fn refill_triples_ring_lpn(&mut self) {
        // Trusted-dealer Ring-LPN seed generation per batch. Both parties
        // derive the same `batch_seed` deterministically from their shared_seed.
        let batch_seed = self
            .shared_seed
            .wrapping_add(0xBEEF * (self.batch_counter + 1));
        let params = self
            .ring_lpn_params
            .as_ref()
            .expect("ring_lpn_params must be set")
            .clone();
        let (seed0, seed1) = RingLpnPcgSeed::<F>::gen_pair_trusted_dealer(params, batch_seed);
        let my_seed = if self.party_id == 0 { seed0 } else { seed1 };
        let ole = my_seed.expand_to_ole();
        let triples = ole_to_beaver_triples(&ole, self.role);
        self.triple_buf = triples;
        self.batch_counter += 1;
    }

    fn refill_triples_trusted_dealer(&mut self) {
        // Generate a fresh PCG seed pair deterministically (both parties derive
        // the same batch seed from shared_seed + batch_counter).
        let batch_seed = self
            .shared_seed
            .wrapping_add(0xA11CE * (self.batch_counter + 1));
        let (p0, p1) = PcgSeed::<F>::gen_pair_insecure(self.params.clone(), batch_seed);
        let my_seed = if self.party_id == 0 { p0 } else { p1 };
        let ole = my_seed.expand();
        let triples = ole_to_beaver_triples(&ole, self.role);
        self.triple_buf = triples;
        self.batch_counter += 1;
    }

    fn make_share(&mut self, val: F) -> SpdzPrimeFieldShare<F> {
        // Trusted-dealer split: derive both shares from shared rng and take ours.
        let s0 = F::rand(&mut self.rng);
        let s1 = val - s0;
        let mac = self.mac_key * val;
        let m0 = F::rand(&mut self.rng);
        let m1 = mac - m0;
        if self.party_id == 0 {
            SpdzPrimeFieldShare::new(s0, m0)
        } else {
            SpdzPrimeFieldShare::new(s1, m1)
        }
    }

    fn refill_randoms(&mut self) {
        for _ in 0..4096 {
            let v = F::rand(&mut self.rng);
            let share = self.make_share(v);
            self.random_buf.push(share);
        }
    }

    fn refill_bits(&mut self) {
        for _ in 0..4096 {
            let coin: bool = self.rng.r#gen();
            let v = if coin { F::one() } else { F::zero() };
            let share = self.make_share(v);
            self.bit_buf.push(share);
        }
    }

    fn refill_input_masks(&mut self) {
        for _ in 0..2048 {
            let r = F::rand(&mut self.rng);
            let s = self.make_share(r);
            if self.party_id == 0 {
                self.input_mask_buf.push((r, s));
            } else {
                self.counter_mask_buf.push(s);
            }
        }
        for _ in 0..2048 {
            let r = F::rand(&mut self.rng);
            let s = self.make_share(r);
            if self.party_id == 1 {
                self.input_mask_buf.push((r, s));
            } else {
                self.counter_mask_buf.push(s);
            }
        }
    }
}

impl<F: PrimeField + ark_ff::FftField> SpdzPreprocessing<F> for PcgPreprocessing<F> {
    fn mac_key_share(&self) -> F {
        self.mac_key_share
    }

    fn next_triple(
        &mut self,
    ) -> eyre::Result<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)> {
        if self.triple_buf.is_empty() {
            self.refill_triples();
        }
        let t = self.triple_buf.pop().unwrap();
        // In mac-free mode, mac field is ignored. Fill with zero.
        let zero = F::zero();
        Ok((
            SpdzPrimeFieldShare::new(t.a, zero),
            SpdzPrimeFieldShare::new(t.b, zero),
            SpdzPrimeFieldShare::new(t.c, zero),
        ))
    }

    fn next_shared_random(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>> {
        if self.random_buf.is_empty() {
            self.refill_randoms();
        }
        Ok(self.random_buf.pop().unwrap())
    }

    fn next_shared_bit(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>> {
        if self.bit_buf.is_empty() {
            self.refill_bits();
        }
        Ok(self.bit_buf.pop().unwrap())
    }

    fn next_input_mask(&mut self) -> eyre::Result<(F, SpdzPrimeFieldShare<F>)> {
        if self.input_mask_buf.is_empty() {
            self.refill_input_masks();
        }
        Ok(self.input_mask_buf.pop().unwrap())
    }

    fn next_counterparty_input_mask(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>> {
        if self.counter_mask_buf.is_empty() {
            self.refill_input_masks();
        }
        Ok(self.counter_mask_buf.pop().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use spdz_core::types::combine_field_element;

    #[test]
    fn test_pcg_preprocessing_triples() {
        let mut p0 = PcgPreprocessing::<Fr>::new_insecure(0, 42, 10);
        let mut p1 = PcgPreprocessing::<Fr>::new_insecure(1, 42, 10);

        // Get 100 triples from each party
        for i in 0..100 {
            let (a0, b0, c0) = p0.next_triple().unwrap();
            let (a1, b1, c1) = p1.next_triple().unwrap();

            let a = combine_field_element(a0, a1);
            let b = combine_field_element(b0, b1);
            let c = combine_field_element(c0, c1);
            assert_eq!(a * b, c, "triple {i} failed the Beaver relation");
        }
    }

    #[test]
    fn test_pcg_preprocessing_mac_key() {
        let p0 = PcgPreprocessing::<Fr>::new_insecure(0, 42, 10);
        let p1 = PcgPreprocessing::<Fr>::new_insecure(1, 42, 10);
        // MAC key shares should sum to the shared MAC key
        assert_eq!(p0.mac_key_share() + p1.mac_key_share(), p0.mac_key);
        assert_eq!(p0.mac_key, p1.mac_key);
    }
}
