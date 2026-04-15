//! Sparse polynomial representation used in the PCG.
//!
//! A t-sparse polynomial over F has at most t non-zero coefficients in a
//! degree-N domain. Represented as a list of `(position, value)` pairs.

use ark_ff::{PrimeField, Zero};
use rand::Rng;

/// A sparse polynomial over F with at most `t` non-zero entries in degree < N.
#[derive(Clone, Debug)]
pub struct SparsePoly<F: PrimeField> {
    /// (position, value) pairs, positions sorted ascending.
    pub entries: Vec<(usize, F)>,
    /// Degree bound (number of coefficient slots).
    pub n: usize,
}

impl<F: PrimeField> SparsePoly<F> {
    /// Generate a random t-sparse polynomial in degree < n.
    pub fn random<R: Rng>(n: usize, t: usize, rng: &mut R) -> Self {
        let mut positions: Vec<usize> = Vec::with_capacity(t);
        while positions.len() < t {
            let p = rng.gen_range(0..n);
            if !positions.contains(&p) {
                positions.push(p);
            }
        }
        positions.sort_unstable();
        let entries = positions
            .into_iter()
            .map(|p| (p, F::rand(rng)))
            .collect();
        Self { entries, n }
    }

    /// Convert to dense coefficient form (length n).
    pub fn to_dense(&self) -> Vec<F> {
        let mut dense = vec![F::zero(); self.n];
        for (pos, val) in &self.entries {
            dense[*pos] = *val;
        }
        dense
    }

    /// Number of non-zero entries.
    pub fn weight(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use rand::SeedableRng;

    #[test]
    fn test_sparse_random() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
        let p: SparsePoly<Fr> = SparsePoly::random(1024, 16, &mut rng);
        assert_eq!(p.weight(), 16);
        assert_eq!(p.n, 1024);
        // Distinct positions
        let positions: std::collections::HashSet<_> = p.entries.iter().map(|e| e.0).collect();
        assert_eq!(positions.len(), 16);
    }

    #[test]
    fn test_to_dense() {
        let entries = vec![(0, Fr::from(7u64)), (5, Fr::from(42u64))];
        let p = SparsePoly::<Fr> { entries, n: 8 };
        let dense = p.to_dense();
        assert_eq!(dense[0], Fr::from(7u64));
        assert_eq!(dense[5], Fr::from(42u64));
        assert_eq!(dense[1], Fr::zero());
        assert_eq!(dense[7], Fr::zero());
    }
}
