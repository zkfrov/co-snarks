//! OLE → Beaver triple conversion.
//!
//! Takes 2 random OLE correlations and produces 1 random Beaver triple
//! without any party-to-party communication. The construction:
//!
//! ```text
//! OLE 1 (indices 2k):   P0 has (x_0, y_0), P1 has (x_1, y_1),
//!                        x_0 * x_1 = y_0 + y_1
//! OLE 2 (indices 2k+1): P0 has (x_0', y_0'), P1 has (x_1', y_1'),
//!                        x_0' * x_1' = y_0' + y_1'
//!
//! Triple (a, b, c = a·b):
//!   a_0 = x_0     b_0 = x_0'
//!   a_1 = x_1'    b_1 = x_1
//!   c_0 = a_0·b_0 + y_0 + y_0'
//!   c_1 = a_1·b_1 + y_1 + y_1'
//! ```
//!
//! This produces RANDOM Beaver triples (a, b are determined by the OLE outputs,
//! not chosen by the parties). The SPDZ online phase uses these to mask chosen
//! secret values via the standard ε = x - a, δ = y - b opening trick.
//!
//! MAC-free mode: triples are produced without MACs. The SNARK provides
//! soundness in our collaborative proving setup.

use ark_ff::PrimeField;

/// A Beaver triple in additive share form (mac-free).
///
/// Across parties:
///   (a_0 + a_1) · (b_0 + b_1) = c_0 + c_1
#[derive(Clone, Copy, Debug)]
pub struct BeaverTripleShare<F: PrimeField> {
    pub a: F,
    pub b: F,
    pub c: F,
}

/// Convert a party's OLE output vector into Beaver triple shares.
///
/// Consumes 2 OLE pairs per triple. Returns `ole.len() / 2` triples.
///
/// The `role` parameter determines whether this is party 0 or party 1:
/// - Party 0: c_i = a_i · b_i + y_{2k} + y_{2k+1}
/// - Party 1: c_i = a_i · b_i + y_{2k} + y_{2k+1}  (same formula by symmetry)
///
/// What differs is the INTERPRETATION of (a_i, b_i) across parties. We use the
/// convention:
///   P0: a = x_{2k},     b = x_{2k+1}
///   P1: a = x_{2k+1},   b = x_{2k}
/// (note the index swap for P1 — this is what makes the cross-terms line up.)
pub fn ole_to_beaver_triples<F: PrimeField>(
    ole: &[(F, F)],
    role: crate::pcg::Role,
) -> Vec<BeaverTripleShare<F>> {
    let n_triples = ole.len() / 2;
    let mut out = Vec::with_capacity(n_triples);

    for k in 0..n_triples {
        let (x0, y0) = ole[2 * k];
        let (x1, y1) = ole[2 * k + 1];

        let (a, b) = match role {
            crate::pcg::Role::P0 => (x0, x1),
            crate::pcg::Role::P1 => (x1, x0),
        };
        let c = a * b + y0 + y1;

        out.push(BeaverTripleShare { a, b, c });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcg::{PcgParams, PcgSeed};
    use ark_bn254::Fr;

    #[test]
    fn test_beaver_from_ole_small() {
        // Generate 256 OLEs → 128 Beaver triples
        let params = PcgParams { log_n: 8 };
        let (p0_seed, p1_seed) = PcgSeed::<Fr>::gen_pair_insecure(params, 42);

        let ole_p0 = p0_seed.expand();
        let ole_p1 = p1_seed.expand();

        let triples_p0 = ole_to_beaver_triples(&ole_p0, crate::pcg::Role::P0);
        let triples_p1 = ole_to_beaver_triples(&ole_p1, crate::pcg::Role::P1);

        assert_eq!(triples_p0.len(), 128);
        assert_eq!(triples_p1.len(), 128);

        // Verify each triple: (a_0 + a_1) * (b_0 + b_1) == (c_0 + c_1)
        let mut failures = 0;
        for i in 0..triples_p0.len() {
            let t0 = &triples_p0[i];
            let t1 = &triples_p1[i];
            let a = t0.a + t1.a;
            let b = t0.b + t1.b;
            let c = t0.c + t1.c;
            if a * b != c {
                failures += 1;
            }
        }
        assert_eq!(
            failures, 0,
            "{}/128 triples failed the Beaver relation",
            failures
        );
    }

    #[test]
    fn test_beaver_from_ole_medium() {
        // 16K OLEs → 8K triples
        let params = PcgParams { log_n: 14 };
        let (p0_seed, p1_seed) = PcgSeed::<Fr>::gen_pair_insecure(params, 1234);

        let ole_p0 = p0_seed.expand();
        let ole_p1 = p1_seed.expand();

        let triples_p0 = ole_to_beaver_triples(&ole_p0, crate::pcg::Role::P0);
        let triples_p1 = ole_to_beaver_triples(&ole_p1, crate::pcg::Role::P1);

        let n = triples_p0.len();
        assert_eq!(n, 1 << 13);
        for i in 0..n {
            let a = triples_p0[i].a + triples_p1[i].a;
            let b = triples_p0[i].b + triples_p1[i].b;
            let c = triples_p0[i].c + triples_p1[i].c;
            assert_eq!(a * b, c, "triple {i} failed");
        }
    }
}
