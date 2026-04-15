//! Core PCG expansion over BN254 Fr — MVP.
//!
//! MVP uses a "trusted-dealer PCG" to validate the expansion math:
//! a dealer generates full polynomials a_0, a_1 and a pre-computed additive
//! split of their product c_0, c_1 in COEFFICIENT form. Each party then
//! locally expands by FFT-ing its (a_i, c_i) pair to evaluation form,
//! producing N pointwise OLE correlations.
//!
//! This exercises:
//! - FFT over BN254 Fr (critical path for any real PCG)
//! - Coefficient-to-eval pipeline
//! - OLE output format consistent with what SPDZ Beaver triples consume
//!
//! What's still missing for a real PCG (to be added in later phases):
//! - LPN-based compression of a_i into short seeds
//! - DMPF for the c_i shares
//! - Actively-secure seed generation protocol

use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Which party role in the OLE correlation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Party 0
    P0,
    /// Party 1
    P1,
}

/// PCG parameters.
#[derive(Clone, Debug)]
pub struct PcgParams {
    /// log2 of the polynomial degree (output length = 2^log_n OLEs).
    pub log_n: usize,
}

impl PcgParams {
    pub fn n(&self) -> usize {
        1usize << self.log_n
    }
}

/// A PCG "seed" in the MVP: trusted-dealer generated.
/// Each party holds its own polynomial `a` and additive share `c` of the
/// cyclic convolution a_0 * a_1 (mod X^N - 1).
pub struct PcgSeed<F: PrimeField + FftField> {
    pub role: Role,
    pub params: PcgParams,
    /// This party's multiplicative polynomial in coefficient form, length N.
    pub a: Vec<F>,
    /// This party's additive share of a_0 * a_1 (cyclic), length N coefficients.
    pub c: Vec<F>,
}

impl<F: PrimeField + FftField> PcgSeed<F> {
    /// Trusted-dealer pair generation. Produces two seeds such that
    /// c_0 + c_1 = a_0 * a_1  (cyclic convolution in F[X]/(X^N - 1)).
    pub fn gen_pair_insecure(params: PcgParams, rng_seed: u64) -> (Self, Self) {
        let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
        let n = params.n();

        let a0: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let a1: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();

        // Cyclic convolution: prod[k] = sum_{i+j ≡ k mod N} a0[i] * a1[j]
        // Compute via FFT on the same-size domain (the domain is multiplicative
        // of order N, so FFT-pointwise-mul-IFFT gives cyclic convolution).
        let domain = Radix2EvaluationDomain::<F>::new(n)
            .expect("FFT domain of size N must exist for BN254");
        let mut e0 = a0.clone();
        let mut e1 = a1.clone();
        domain.fft_in_place(&mut e0);
        domain.fft_in_place(&mut e1);
        for (x, y) in e0.iter_mut().zip(e1.iter()) {
            *x *= y;
        }
        domain.ifft_in_place(&mut e0);
        let prod_cyclic = e0; // a0 * a1 mod X^N - 1, in coefficient form, length N.

        // Split additively: c0 random, c1 = prod - c0.
        let c0: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let c1: Vec<F> = prod_cyclic.iter().zip(c0.iter()).map(|(p, c)| *p - *c).collect();

        let p0 = PcgSeed { role: Role::P0, params: params.clone(), a: a0, c: c0 };
        let p1 = PcgSeed { role: Role::P1, params, a: a1, c: c1 };
        (p0, p1)
    }

    /// Local expansion: FFT both the a and c polynomials to evaluation form,
    /// producing N OLE correlations.
    ///
    /// Returns N pairs (x_i, y_i) such that across both parties:
    ///   x_0[k] * x_1[k] = y_0[k] + y_1[k]   for k in 0..N
    pub fn expand(&self) -> Vec<(F, F)> {
        let n = self.params.n();
        let domain = Radix2EvaluationDomain::<F>::new(n)
            .expect("FFT domain of size N must exist for BN254");

        let mut x = self.a.clone();
        let mut y = self.c.clone();
        domain.fft_in_place(&mut x);
        domain.fft_in_place(&mut y);

        x.into_iter().zip(y.into_iter()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    fn assert_ole_correct(out0: &[(Fr, Fr)], out1: &[(Fr, Fr)]) {
        assert_eq!(out0.len(), out1.len());
        let mut failures = 0;
        for i in 0..out0.len() {
            let (x0, y0) = out0[i];
            let (x1, y1) = out1[i];
            if x0 * x1 != y0 + y1 {
                failures += 1;
            }
        }
        assert_eq!(
            failures, 0,
            "{} OLE correlations failed out of {}",
            failures,
            out0.len()
        );
    }

    #[test]
    fn test_ole_correctness_small() {
        let params = PcgParams { log_n: 8 };
        let (p0, p1) = PcgSeed::<Fr>::gen_pair_insecure(params, 42);
        let out0 = p0.expand();
        let out1 = p1.expand();
        assert_eq!(out0.len(), 256);
        assert_ole_correct(&out0, &out1);
    }

    #[test]
    fn test_ole_correctness_medium() {
        let params = PcgParams { log_n: 14 }; // 16K OLEs
        let (p0, p1) = PcgSeed::<Fr>::gen_pair_insecure(params, 1234);
        let out0 = p0.expand();
        let out1 = p1.expand();
        assert_eq!(out0.len(), 1 << 14);
        assert_ole_correct(&out0, &out1);
    }
}
