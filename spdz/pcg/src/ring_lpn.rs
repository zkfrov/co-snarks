//! Ring-LPN primitives for the sub-linear PCG construction.
//!
//! Operates in the ring R = F[X]/(X^N - 1) — cyclic polynomial multiplication
//! over BN254 Fr. This ring has efficient FFT (N must be a power of 2 ≤ 2^28
//! for BN254's smooth subgroup).
//!
//! Two primitives:
//! - `cyclic_conv_dense`: dense × dense cyclic convolution via FFT
//! - `sparse_cyclic_mul`: sparse × sparse cyclic convolution, returning a
//!   sparse result with at most |x| · |y| non-zero entries

use crate::sparse::SparsePoly;
use ark_ff::{FftField, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

/// Dense cyclic convolution `a * b mod (X^N - 1)`. Both inputs must have
/// length N (a power of 2 within BN254's smooth subgroup).
pub fn cyclic_conv_dense<F: PrimeField + FftField>(a: &[F], b: &[F]) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    let domain = Radix2EvaluationDomain::<F>::new(n)
        .expect("FFT domain of size N must exist");
    let mut ea = a.to_vec();
    let mut eb = b.to_vec();
    domain.fft_in_place(&mut ea);
    domain.fft_in_place(&mut eb);
    for (x, y) in ea.iter_mut().zip(eb.iter()) {
        *x *= y;
    }
    domain.ifft_in_place(&mut ea);
    ea
}

/// Sparse cyclic multiplication. Computes `x * y mod (X^N - 1)` where both
/// inputs are t-sparse polynomials in degree < N. Result may have up to
/// `|x.entries| · |y.entries|` non-zero entries (fewer if modular collisions
/// sum to zero, which is a measure-zero event over a prime field).
///
/// Output is returned as a dense length-N vector. The result is t²-sparse
/// (in the worst case) but we produce the dense form for downstream use
/// (DMPF encoding, further cyclic convs, etc.).
pub fn sparse_cyclic_mul_dense<F: PrimeField>(
    x: &SparsePoly<F>,
    y: &SparsePoly<F>,
) -> Vec<F> {
    assert_eq!(x.n, y.n);
    let n = x.n;
    let mut out = vec![F::zero(); n];
    for (i, xv) in &x.entries {
        for (j, yv) in &y.entries {
            let k = (i + j) % n;
            out[k] += *xv * *yv;
        }
    }
    out
}

/// Same as [`sparse_cyclic_mul_dense`] but returns the result as a sparse
/// polynomial (only collecting non-zero entries). Output sparsity can be
/// up to `|x| · |y|`; this is useful when feeding into a DMPF.
pub fn sparse_cyclic_mul_sparse<F: PrimeField>(
    x: &SparsePoly<F>,
    y: &SparsePoly<F>,
) -> SparsePoly<F> {
    let dense = sparse_cyclic_mul_dense(x, y);
    let entries: Vec<(usize, F)> = dense
        .into_iter()
        .enumerate()
        .filter(|(_, v)| !v.is_zero())
        .collect();
    SparsePoly {
        entries,
        n: x.n,
    }
}

/// LPN-style code expansion: `u = a * s` in the ring R = F[X]/(X^N - 1).
///
/// `a` is the public random polynomial of length N (shared by both parties).
/// `s` is the party's secret sparse polynomial.
///
/// Uses sparse × dense multiplication: for each non-zero (pos, val) in s,
/// adds `val · a[(k - pos) mod N]` to u[k]. This is O(N · t) field ops —
/// faster than FFT for small t.
pub fn lpn_expand<F: PrimeField>(a: &[F], s: &SparsePoly<F>) -> Vec<F> {
    let n = a.len();
    assert_eq!(n, s.n);
    let mut u = vec![F::zero(); n];
    for (pos, val) in &s.entries {
        // u[k] += val * a[(k - pos) mod N]  for all k in 0..N
        // Equivalent: u[(k + pos) mod N] += val * a[k] for all k in 0..N
        for k in 0..n {
            let dst = (k + pos) % n;
            u[dst] += *val * a[k];
        }
    }
    u
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_sparse_mul_matches_dense() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let n = 256;

        let x = SparsePoly::<Fr>::random(n, 4, &mut rng);
        let y = SparsePoly::<Fr>::random(n, 4, &mut rng);

        // Ground truth: dense conv.
        let x_dense = x.to_dense();
        let y_dense = y.to_dense();
        let expected = cyclic_conv_dense(&x_dense, &y_dense);

        // Sparse conv.
        let got = sparse_cyclic_mul_dense(&x, &y);
        assert_eq!(got, expected, "sparse conv disagreed with FFT conv");
    }

    #[test]
    fn test_lpn_expand_matches_cyclic_conv() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let n = 64;
        let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let s = SparsePoly::<Fr>::random(n, 8, &mut rng);

        // Reference: cyclic conv of dense a with dense s.
        let s_dense = s.to_dense();
        let expected = cyclic_conv_dense(&a, &s_dense);

        let got = lpn_expand(&a, &s);
        assert_eq!(got, expected, "lpn_expand disagreed with cyclic conv");
    }
}
