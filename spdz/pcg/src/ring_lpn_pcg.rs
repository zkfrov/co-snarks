//! Sub-linear PCG from Ring-LPN (Boyle et al. CRYPTO 2020).
//!
//! Each party holds:
//! - `s_i` — sparse polynomial, weight t
//! - `e_i` — sparse polynomial, weight t
//! - Computed locally: `u_i = a · s_i` (cyclic conv with public `a`), then
//!   `a_i = u_i + e_i` — the party's "OLE input" polynomial.
//!
//! The cross-term identity:
//! ```text
//! a_0 · a_1 = (u_0+e_0)(u_1+e_1)
//!            = a² · (s_0·s_1) + a · (s_0·e_1) + a · (s_1·e_0) + (e_0·e_1)
//! ```
//!
//! All 4 cross-products are **sparse × sparse** (up to t² non-zeros each).
//! Each cross-product's additive share is distributed via a DMPF. Each party
//! locally:
//! 1. Expands the 4 DMPFs to length-N vectors
//! 2. Applies cyclic conv with `a` or `a²` (public) as needed
//! 3. Sums contributions → `c_i` share of `a_0 · a_1`
//!
//! Bandwidth: dominated by 4 DMPF keys, each ≈ B·log(3N/B)·λ bytes where B is
//! the number of DMPF buckets (~1.5·t²). For t=128, N=2^20: ~512 KB per
//! party. Asymptotically sub-linear in N (scales with t², not N).
//!
//! This module implements the TRUSTED-DEALER version of the seed generation.
//! Real 2-party key gen comes in Phase 2b.2e using OT.

use crate::dmpf::{eval_all as dmpf_eval_all, gen_dmpf, DmpfKey};
use crate::dmpf_gen_protocol::DmpfGenProtocol;
use crate::pcg::Role;
use crate::ring_lpn::{cyclic_conv_dense, lpn_expand, sparse_cyclic_mul_dense};
use crate::sparse::SparsePoly;
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Ring-LPN PCG parameters.
#[derive(Clone, Debug)]
pub struct RingLpnPcgParams<F: PrimeField + FftField> {
    /// log2 of the ring dimension (N = 2^log_n).
    pub log_n: u32,
    /// Sparsity parameter: each of s_i, e_i has t non-zero entries.
    pub t: usize,
    /// Public "LPN code" polynomial: the public `a` used as `u_i = a · s_i`.
    /// Length N. Shared by both parties.
    pub a: Vec<F>,
    /// Cached `a²` (cyclic conv of a with itself). Length N. Used for the
    /// u_0·u_1 cross-term.
    pub a_sq: Vec<F>,
}

impl<F: PrimeField + FftField> RingLpnPcgParams<F> {
    pub fn new(log_n: u32, t: usize, a_seed: u64) -> Self {
        use ark_ff::UniformRand;
        let n = 1usize << log_n;
        let mut rng = ChaCha20Rng::seed_from_u64(a_seed);
        let a: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let a_sq = cyclic_conv_dense(&a, &a);
        Self { log_n, t, a, a_sq }
    }

    pub fn n(&self) -> usize {
        1usize << self.log_n
    }
}

/// A party's PCG seed: its private sparse polys + DMPF keys for each cross-term.
pub struct RingLpnPcgSeed<F: PrimeField + FftField> {
    pub role: Role,
    pub params: RingLpnPcgParams<F>,
    /// Private sparse polynomial `s_i` (LPN secret).
    pub s: SparsePoly<F>,
    /// Private sparse polynomial `e_i` (LPN noise).
    pub e: SparsePoly<F>,
    /// DMPF key for shares of `s_0 · s_1`.
    pub dmpf_ss: DmpfKey<F>,
    /// DMPF key for shares of `s_0 · e_1`.
    pub dmpf_se: DmpfKey<F>,
    /// DMPF key for shares of `s_1 · e_0`.
    pub dmpf_es: DmpfKey<F>,
    /// DMPF key for shares of `e_0 · e_1`.
    pub dmpf_ee: DmpfKey<F>,
}

impl<F: PrimeField + FftField> RingLpnPcgSeed<F> {
    /// Trusted-dealer seed pair generation. Produces two seeds such that
    /// local expansion yields OLE correlations with shares of `a_0 · a_1`.
    pub fn gen_pair_trusted_dealer(
        params: RingLpnPcgParams<F>,
        rng_seed: u64,
    ) -> (Self, Self) {
        let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
        let n = params.n();
        let t = params.t;

        // Each party's private sparse polys.
        let s0 = SparsePoly::<F>::random(n, t, &mut rng);
        let s1 = SparsePoly::<F>::random(n, t, &mut rng);
        let e0 = SparsePoly::<F>::random(n, t, &mut rng);
        let e1 = SparsePoly::<F>::random(n, t, &mut rng);

        // Compute the 4 cross-products (sparse × sparse, dense result of length N).
        let ss = sparse_cyclic_mul_dense(&s0, &s1);
        let se = sparse_cyclic_mul_dense(&s0, &e1);
        let es = sparse_cyclic_mul_dense(&s1, &e0);
        let ee = sparse_cyclic_mul_dense(&e0, &e1);

        // Convert to (pos, val) lists for DMPF gen.
        fn dense_to_points<G: PrimeField>(v: &[G]) -> Vec<(u64, G)> {
            v.iter()
                .enumerate()
                .filter(|(_, val)| !val.is_zero())
                .map(|(i, val)| (i as u64, *val))
                .collect()
        }

        // Build DMPFs encoding the shares of each cross-term.
        // The DMPF encodes the FULL cross-term (not split); we split in `expand()`
        // by choosing P0's share = DMPF output, P1's share = -DMPF output + cross-term.
        // Actually that requires non-randomized splits. Let's use a cleaner approach:
        //   dmpf encodes the cross term X.
        //   P0's DMPF key produces v0 at each position; P1's produces v1.
        //   v0[k] + v1[k] = X[k]  (by DMPF correctness).
        // So each party's "share" of X is just their DMPF eval output.
        // No additional splitting needed.
        let ss_pts = dense_to_points(&ss);
        let se_pts = dense_to_points(&se);
        let es_pts = dense_to_points(&es);
        let ee_pts = dense_to_points(&ee);

        use rand::Rng;
        let (dmpf_ss_0, dmpf_ss_1) = gen_dmpf::<F>(params.log_n, &ss_pts, rng.r#gen());
        let (dmpf_se_0, dmpf_se_1) = gen_dmpf::<F>(params.log_n, &se_pts, rng.r#gen());
        let (dmpf_es_0, dmpf_es_1) = gen_dmpf::<F>(params.log_n, &es_pts, rng.r#gen());
        let (dmpf_ee_0, dmpf_ee_1) = gen_dmpf::<F>(params.log_n, &ee_pts, rng.r#gen());

        let seed_p0 = RingLpnPcgSeed {
            role: Role::P0,
            params: params.clone(),
            s: s0,
            e: e0,
            dmpf_ss: dmpf_ss_0,
            dmpf_se: dmpf_se_0,
            dmpf_es: dmpf_es_0,
            dmpf_ee: dmpf_ee_0,
        };
        let seed_p1 = RingLpnPcgSeed {
            role: Role::P1,
            params,
            s: s1,
            e: e1,
            dmpf_ss: dmpf_ss_1,
            dmpf_se: dmpf_se_1,
            dmpf_es: dmpf_es_1,
            dmpf_ee: dmpf_ee_1,
        };
        (seed_p0, seed_p1)
    }

    /// Phase 2b.2e: generate this party's seed using a 2-party DMPF generation
    /// protocol. Each party calls this with:
    /// - its own private sparse polys `my_s`, `my_e`
    /// - 4 protocol instances (one per cross-term)
    ///
    /// Protocol assignments (by cross-term):
    /// - `proto_ss`: computes s_0 · s_1 — P0 submits s_0, P1 submits s_1
    /// - `proto_se`: computes s_0 · e_1 — P0 submits s_0, P1 submits e_1
    /// - `proto_es`: computes s_1 · e_0 — P0 submits e_0, P1 submits s_1
    /// - `proto_ee`: computes e_0 · e_1 — P0 submits e_0, P1 submits e_1
    pub fn gen_with_protocols(
        role: Role,
        params: RingLpnPcgParams<F>,
        my_s: SparsePoly<F>,
        my_e: SparsePoly<F>,
        proto_ss: &mut dyn DmpfGenProtocol<F>,
        proto_se: &mut dyn DmpfGenProtocol<F>,
        proto_es: &mut dyn DmpfGenProtocol<F>,
        proto_ee: &mut dyn DmpfGenProtocol<F>,
    ) -> eyre::Result<Self> {
        // Inputs to each protocol depend on role.
        let (ss_in, se_in, es_in, ee_in) = match role {
            Role::P0 => (&my_s, &my_s, &my_e, &my_e),
            Role::P1 => (&my_s, &my_e, &my_s, &my_e),
        };

        let dmpf_ss = proto_ss.gen_dmpf_share(ss_in, params.log_n)?;
        let dmpf_se = proto_se.gen_dmpf_share(se_in, params.log_n)?;
        let dmpf_es = proto_es.gen_dmpf_share(es_in, params.log_n)?;
        let dmpf_ee = proto_ee.gen_dmpf_share(ee_in, params.log_n)?;

        Ok(RingLpnPcgSeed {
            role,
            params,
            s: my_s,
            e: my_e,
            dmpf_ss,
            dmpf_se,
            dmpf_es,
            dmpf_ee,
        })
    }

    /// Local expansion: produces this party's (a_i, c_i) pair — the input
    /// to the PCG's OLE output. Caller must FFT both to eval form to get
    /// N pointwise OLE correlations.
    ///
    /// Returns (a, c) in coefficient form, length N each.
    pub fn expand(&self) -> (Vec<F>, Vec<F>) {
        let n = self.params.n();

        // Step 1: Compute a_i = u_i + e_i locally.
        let u = lpn_expand(&self.params.a, &self.s);
        let mut a_poly = u;
        for (pos, val) in &self.e.entries {
            a_poly[*pos] += *val;
        }

        // Step 2: Expand each DMPF to length-N share vectors.
        let share_ss = dmpf_eval_all(&self.dmpf_ss);
        let share_se = dmpf_eval_all(&self.dmpf_se);
        let share_es = dmpf_eval_all(&self.dmpf_es);
        let share_ee = dmpf_eval_all(&self.dmpf_ee);

        // Step 3: Compose c_i = a² · share_ss + a · share_se + a · share_es + share_ee
        // (with cyclic convs applied locally on public a, a²).
        let term_ss = cyclic_conv_dense(&self.params.a_sq, &share_ss);
        let term_se = cyclic_conv_dense(&self.params.a, &share_se);
        let term_es = cyclic_conv_dense(&self.params.a, &share_es);
        // term_ee is share_ee directly (no multiplication needed).

        let mut c = vec![F::zero(); n];
        for i in 0..n {
            c[i] = term_ss[i] + term_se[i] + term_es[i] + share_ee[i];
        }

        (a_poly, c)
    }

    /// Produce the N OLE correlations in eval form: (x_i, y_i) pairs such
    /// that across both parties x_0[k]·x_1[k] = y_0[k] + y_1[k].
    ///
    /// Convenience wrapper: calls `expand()` and FFTs both to eval form.
    pub fn expand_to_ole(&self) -> Vec<(F, F)> {
        let n = self.params.n();
        let (mut a_poly, mut c) = self.expand();

        let domain = Radix2EvaluationDomain::<F>::new(n)
            .expect("FFT domain of size N must exist");
        domain.fft_in_place(&mut a_poly);
        domain.fft_in_place(&mut c);

        a_poly.into_iter().zip(c.into_iter()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn ring_lpn_pcg_ole_correctness_small() {
        // Small instance: N=2^8, t=4.
        let params = RingLpnPcgParams::<Fr>::new(8, 4, 999);
        let (seed0, seed1) = RingLpnPcgSeed::<Fr>::gen_pair_trusted_dealer(params, 42);

        let ole0 = seed0.expand_to_ole();
        let ole1 = seed1.expand_to_ole();

        assert_eq!(ole0.len(), 256);
        assert_eq!(ole1.len(), 256);

        let mut failures = 0;
        for i in 0..ole0.len() {
            let (x0, y0) = ole0[i];
            let (x1, y1) = ole1[i];
            if x0 * x1 != y0 + y1 {
                failures += 1;
            }
        }
        assert_eq!(failures, 0, "{failures}/256 OLE correlations failed");
    }

    /// Phase 2b.2e.0: each party runs `gen_with_protocols` using mock 2-party
    /// DMPF generation protocols. Produces the same OLE correlations as the
    /// trusted-dealer version, but with a protocol-shaped API.
    #[test]
    fn ring_lpn_pcg_via_mock_protocols() {
        use crate::dmpf_gen_protocol::MockDmpfGenProtocol;
        use crate::sparse::SparsePoly;

        let log_n = 10u32;
        let t = 8;
        let params = RingLpnPcgParams::<Fr>::new(log_n, t, 0xA11C0DE);

        // Each party picks its own sparse polys (independently; neither
        // knows the other's).
        let mut rng0 = rand_chacha::ChaCha20Rng::seed_from_u64(100);
        let mut rng1 = rand_chacha::ChaCha20Rng::seed_from_u64(200);
        let n = params.n();
        let s0 = SparsePoly::<Fr>::random(n, t, &mut rng0);
        let e0 = SparsePoly::<Fr>::random(n, t, &mut rng0);
        let s1 = SparsePoly::<Fr>::random(n, t, &mut rng1);
        let e1 = SparsePoly::<Fr>::random(n, t, &mut rng1);

        // One protocol pair per cross-term (4 total).
        let (mut ss_p0, mut ss_p1) = MockDmpfGenProtocol::<Fr>::new_pair(1);
        let (mut se_p0, mut se_p1) = MockDmpfGenProtocol::<Fr>::new_pair(2);
        let (mut es_p0, mut es_p1) = MockDmpfGenProtocol::<Fr>::new_pair(3);
        let (mut ee_p0, mut ee_p1) = MockDmpfGenProtocol::<Fr>::new_pair(4);

        let params_clone = params.clone();
        let (s0c, e0c) = (s0.clone(), e0.clone());
        let (s1c, e1c) = (s1.clone(), e1.clone());

        let h0 = std::thread::spawn(move || {
            RingLpnPcgSeed::gen_with_protocols(
                Role::P0,
                params_clone,
                s0c,
                e0c,
                &mut ss_p0,
                &mut se_p0,
                &mut es_p0,
                &mut ee_p0,
            )
            .unwrap()
        });
        let params_clone2 = params.clone();
        let h1 = std::thread::spawn(move || {
            RingLpnPcgSeed::gen_with_protocols(
                Role::P1,
                params_clone2,
                s1c,
                e1c,
                &mut ss_p1,
                &mut se_p1,
                &mut es_p1,
                &mut ee_p1,
            )
            .unwrap()
        });

        let seed0 = h0.join().unwrap();
        let seed1 = h1.join().unwrap();

        let ole0 = seed0.expand_to_ole();
        let ole1 = seed1.expand_to_ole();
        assert_eq!(ole0.len(), n);

        for i in 0..n {
            let (x0, y0) = ole0[i];
            let (x1, y1) = ole1[i];
            assert_eq!(x0 * x1, y0 + y1, "OLE at position {i} failed");
        }
    }

    #[test]
    fn ring_lpn_pcg_ole_larger() {
        // N = 2^14 = 16K OLEs, t = 16 → 4 × 256 = 1024 total DMPF points.
        let t = std::time::Instant::now();
        let params = RingLpnPcgParams::<Fr>::new(14, 16, 5555);
        eprintln!("[test] params: {:.2}s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let (seed0, seed1) = RingLpnPcgSeed::<Fr>::gen_pair_trusted_dealer(params, 88);
        eprintln!("[test] gen: {:.2}s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let ole0 = seed0.expand_to_ole();
        let ole1 = seed1.expand_to_ole();
        eprintln!("[test] expand both: {:.2}s", t.elapsed().as_secs_f64());
        for i in 0..ole0.len() {
            assert_eq!(ole0[i].0 * ole1[i].0, ole0[i].1 + ole1[i].1, "pos {i}");
        }
    }

    #[test]
    fn ring_lpn_pcg_ole_medium() {
        let t = std::time::Instant::now();
        let params = RingLpnPcgParams::<Fr>::new(10, 8, 1234);
        eprintln!("[test] params built: {:.2}s", t.elapsed().as_secs_f64());

        let t = std::time::Instant::now();
        let (seed0, seed1) = RingLpnPcgSeed::<Fr>::gen_pair_trusted_dealer(params, 77);
        eprintln!("[test] gen_pair_trusted_dealer: {:.2}s", t.elapsed().as_secs_f64());

        let t = std::time::Instant::now();
        let ole0 = seed0.expand_to_ole();
        eprintln!("[test] expand_to_ole p0: {:.2}s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let ole1 = seed1.expand_to_ole();
        eprintln!("[test] expand_to_ole p1: {:.2}s", t.elapsed().as_secs_f64());

        assert_eq!(ole0.len(), 1024);

        for i in 0..ole0.len() {
            let (x0, y0) = ole0[i];
            let (x1, y1) = ole1[i];
            assert_eq!(x0 * x1, y0 + y1, "OLE at position {i} failed");
        }
    }
}
