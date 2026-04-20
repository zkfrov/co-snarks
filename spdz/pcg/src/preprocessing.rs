//! SpdzPreprocessing adapter backed by the PCG.
//!
//! Triples come from the PCG's OLE expansion (Ring-LPN or oblivious DPF).
//! Shared randoms, bits, and input masks use a trusted-dealer construction
//! (not on the critical path; easy to replace later with dedicated generators).

use pcg_core::pcg::Role;
use pcg_core::ring_lpn_pcg::RingLpnPcgParams;
use pcg_core::triples::{ole_to_beaver_triples, BeaverTripleShare};
use ark_ff::PrimeField;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use spdz_core::preprocessing::SpdzPreprocessing;
use spdz_core::SpdzPrimeFieldShare;

#[cfg(feature = "gc")]
use crate::dmpf_oblivious::Seed2PartyOblivious;

pub struct PcgPreprocessing<F: PrimeField + ark_ff::FftField> {
    party_id: usize,
    role: Role,
    mac_key_share: F,
    /// Only populated in insecure modes; used by tests to sanity-check.
    pub(crate) mac_key: F,
    rng: ChaCha20Rng,

    // Current batch of triples from the most-recent expansion.
    triple_buf: Vec<BeaverTripleShare<F>>,

    // Non-triple material (trusted-dealer style for MVP).
    random_buf: Vec<SpdzPrimeFieldShare<F>>,
    bit_buf: Vec<SpdzPrimeFieldShare<F>>,
    input_mask_buf: Vec<(F, SpdzPrimeFieldShare<F>)>,
    counter_mask_buf: Vec<SpdzPrimeFieldShare<F>>,

    log_n: usize,
    batch_counter: u64,
    shared_seed: u64,

    /// Ring-LPN PCG parameters. When present, `refill_triples` uses the
    /// sub-linear Ring-LPN construction with trusted-dealer seeds.
    ring_lpn_params: Option<RingLpnPcgParams<F>>,
    ring_lpn_t: usize,

    /// Oblivious PCG seeds: pre-generated via `gen_seed_2party_oblivious`.
    /// `refill_triples` pops one seed per call and expands to triples.
    #[cfg(feature = "gc")]
    oblivious_seeds: Vec<Seed2PartyOblivious<F>>,
}

unsafe impl<F: PrimeField + ark_ff::FftField> Send for PcgPreprocessing<F> {}

impl<F: PrimeField + ark_ff::FftField> PcgPreprocessing<F> {
    /// Helper: derive MAC key shares from a shared seed.
    fn derive_mac_keys(shared_seed: u64, party_id: usize) -> (F, F, F) {
        let mut seed_rng = ChaCha20Rng::seed_from_u64(shared_seed);
        let mac_key = F::rand(&mut seed_rng);
        let mk0 = F::rand(&mut seed_rng);
        let mk1 = mac_key - mk0;
        let mac_key_share = if party_id == 0 { mk0 } else { mk1 };
        (mac_key, mac_key_share, mac_key)
    }

    /// Ring-LPN PCG constructor with trusted-dealer seed generation.
    ///
    /// Both parties call with the SAME `shared_seed`, `log_n`, `t`, and
    /// `a_seed`. Each batch's dealer seed is derived deterministically.
    ///
    /// **INSECURE** (shared dealer seed). Use the oblivious constructor
    /// for production.
    pub fn new_ring_lpn_insecure(
        party_id: usize,
        shared_seed: u64,
        log_n: u32,
        t: usize,
        a_seed: u64,
    ) -> Self {
        assert!(party_id == 0 || party_id == 1);
        let role = if party_id == 0 { Role::P0 } else { Role::P1 };
        let (mac_key, mac_key_share, _) = Self::derive_mac_keys(shared_seed, party_id);
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
            log_n: log_n as usize,
            batch_counter: 0,
            shared_seed,
            ring_lpn_params: Some(ring_lpn_params),
            ring_lpn_t: t,
            #[cfg(feature = "gc")]
            oblivious_seeds: Vec::new(),
        }
    }

    /// Convenience alias for backward compatibility.
    pub fn new_insecure(party_id: usize, shared_seed: u64, log_n: usize) -> Self {
        // Use Ring-LPN with small t for insecure/testing mode.
        Self::new_ring_lpn_insecure(party_id, shared_seed, log_n as u32, 4, 0xA11CE)
    }

    /// Oblivious constructor: builds SPDZ preprocessing on top of
    /// `gen_seed_2party_oblivious`. The resulting triples come from a PCG
    /// batch generated **without leaking sparse-poly positions** to either party.
    #[cfg(feature = "gc")]
    pub fn new_ring_lpn_oblivious<N, OT>(
        party_id: usize,
        shared_seed: u64,
        private_seed: u64,
        log_n: u32,
        t: usize,
        a_seed: u64,
        prg_session: &mut crate::Prg2pcSession<N>,
        bit_ot: &mut OT,
    ) -> eyre::Result<Self>
    where
        F: ark_ff::FftField,
        N: mpc_net::Network + Unpin + 'static,
        OT: pcg_protocols::BitOt,
    {
        use pcg_core::sparse::SparsePoly;

        eyre::ensure!(party_id == 0 || party_id == 1, "party_id must be 0 or 1");
        let role = if party_id == 0 { Role::P0 } else { Role::P1 };
        let (mac_key, mac_key_share, _) = Self::derive_mac_keys(shared_seed, party_id);
        let rng = ChaCha20Rng::seed_from_u64(shared_seed.wrapping_add(party_id as u64));

        let mut sparse_rng = ChaCha20Rng::seed_from_u64(private_seed);
        let n = 1usize << log_n;
        let s = SparsePoly::<F>::random(n, t, &mut sparse_rng);
        let e = SparsePoly::<F>::random(n, t, &mut sparse_rng);

        let pcg_params = RingLpnPcgParams::<F>::new(log_n, t, a_seed);
        let oblivious_seed = crate::dmpf_oblivious::gen_seed_2party_oblivious::<F, N, OT>(
            prg_session, bit_ot, role, pcg_params, s, e,
        )?;

        Ok(Self {
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
            log_n: log_n as usize,
            batch_counter: 0,
            shared_seed,
            ring_lpn_params: None,
            ring_lpn_t: 0,
            #[cfg(feature = "gc")]
            oblivious_seeds: vec![oblivious_seed],
        })
    }

    /// Multi-batch oblivious constructor: pre-generates `n_batches`
    /// independent PCG batches. All batches reuse the same `Prg2pcSession`
    /// so Ferret bootstrap amortizes.
    #[cfg(feature = "gc")]
    pub fn new_ring_lpn_oblivious_batched<N, OT>(
        party_id: usize,
        shared_seed: u64,
        private_seed: u64,
        log_n: u32,
        t: usize,
        a_seed: u64,
        n_batches: usize,
        prg_session: &mut crate::Prg2pcSession<N>,
        bit_ot: &mut OT,
    ) -> eyre::Result<Self>
    where
        F: ark_ff::FftField,
        N: mpc_net::Network + Unpin + 'static,
        OT: pcg_protocols::BitOt,
    {
        use pcg_core::sparse::SparsePoly;

        eyre::ensure!(party_id == 0 || party_id == 1, "party_id must be 0 or 1");
        eyre::ensure!(n_batches >= 1, "n_batches must be >= 1");
        let role = if party_id == 0 { Role::P0 } else { Role::P1 };
        let (mac_key, mac_key_share, _) = Self::derive_mac_keys(shared_seed, party_id);
        let rng = ChaCha20Rng::seed_from_u64(shared_seed.wrapping_add(party_id as u64));

        let mut sparse_rng = ChaCha20Rng::seed_from_u64(private_seed);
        let n = 1usize << log_n;
        let pcg_params = RingLpnPcgParams::<F>::new(log_n, t, a_seed);

        let mut oblivious_seeds = Vec::with_capacity(n_batches);
        for _ in 0..n_batches {
            let s = SparsePoly::<F>::random(n, t, &mut sparse_rng);
            let e = SparsePoly::<F>::random(n, t, &mut sparse_rng);
            let seed = crate::dmpf_oblivious::gen_seed_2party_oblivious::<F, N, OT>(
                prg_session, bit_ot, role, pcg_params.clone(), s, e,
            )?;
            oblivious_seeds.push(seed);
        }

        Ok(Self {
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
            log_n: log_n as usize,
            batch_counter: 0,
            shared_seed,
            ring_lpn_params: None,
            ring_lpn_t: 0,
            oblivious_seeds,
        })
    }

    fn refill_triples(&mut self) {
        #[cfg(feature = "gc")]
        if !self.oblivious_seeds.is_empty() {
            self.refill_triples_oblivious();
            return;
        }
        if self.ring_lpn_params.is_some() {
            self.refill_triples_ring_lpn();
        } else {
            panic!("no triple source configured");
        }
    }

    #[cfg(feature = "gc")]
    fn refill_triples_oblivious(&mut self) {
        assert!(
            !self.oblivious_seeds.is_empty(),
            "all pre-generated oblivious PCG batches consumed"
        );
        let seed = self.oblivious_seeds.remove(0);
        let ole = seed.expand_to_ole();
        let triples = ole_to_beaver_triples(&ole, self.role);
        self.triple_buf = triples;
        self.batch_counter += 1;
    }

    fn refill_triples_ring_lpn(&mut self) {
        // pcg-core's "testing" feature is enabled in our Cargo.toml dependency,
        // so RingLpnPcgSeed::gen_pair_trusted_dealer is always available here.
        use pcg_core::ring_lpn_pcg::RingLpnPcgSeed;
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

    fn make_share(&mut self, val: F) -> SpdzPrimeFieldShare<F> {
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
        let mut p0 = PcgPreprocessing::<Fr>::new_ring_lpn_insecure(0, 42, 10, 4, 0xA11CE);
        let mut p1 = PcgPreprocessing::<Fr>::new_ring_lpn_insecure(1, 42, 10, 4, 0xA11CE);

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
        let p0 = PcgPreprocessing::<Fr>::new_ring_lpn_insecure(0, 42, 10, 4, 0xA11CE);
        let p1 = PcgPreprocessing::<Fr>::new_ring_lpn_insecure(1, 42, 10, 4, 0xA11CE);
        assert_eq!(p0.mac_key_share() + p1.mac_key_share(), p0.mac_key);
        assert_eq!(p0.mac_key, p1.mac_key);
    }
}
