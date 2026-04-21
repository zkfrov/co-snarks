// Multilinear Batching Sumcheck
//
// A specialized sumcheck that reduces two polynomial evaluation claims
// to a single claim at a new random point.
//
// Given:
//   Accumulator: P_acc(r_acc) = v_acc
//   Instance:    P_inst(r_inst) = v_inst
//
// The sumcheck proves:
//   Σ_x [ P_acc(x)·eq(x, r_acc) + α·P_inst(x)·eq(x, r_inst) ] = v_acc + α·v_inst
//
// where eq(x, r) is the multilinear equality polynomial:
//   eq(x, r) = Π_i ((1-x_i)(1-r_i) + x_i·r_i)
//
// After the sumcheck, both claims are reduced to evaluations at a new
// random point u, enabling a single polynomial opening.
//
// Reference: barretenberg/multilinear_batching/

use ark_ff::{One, PrimeField, Zero};
use co_noir_common::polynomials::polynomial::Polynomial;

/// Compute the multilinear equality polynomial eq(x, r) evaluated at x.
///
/// eq(x, r) = Π_i ((1 - x_i)(1 - r_i) + x_i · r_i)
///
/// For a boolean hypercube point x ∈ {0,1}^n:
///   eq(x, r) = 1 if x = r, 0 otherwise (on the hypercube)
///
/// But we need it as a polynomial in x for the sumcheck, so we evaluate
/// it as a multilinear extension over the full domain.
///
/// Returns a vector of length 2^n with eq(x, r) for all x ∈ {0,1}^n.
pub fn compute_eq_polynomial<F: PrimeField>(r: &[F]) -> Vec<F> {
    let n = r.len();
    let size = 1 << n;
    let mut eq = vec![F::zero(); size];
    eq[0] = F::one();

    for (i, &r_i) in r.iter().enumerate() {
        let half = 1 << i;
        // For each existing value, split into (1-r_i) and r_i branches
        for j in (0..half).rev() {
            eq[2 * j + 1] = eq[j] * r_i;
            eq[2 * j] = eq[j] * (F::one() - r_i);
        }
    }
    eq
}

/// Run the multilinear batching sumcheck.
///
/// Proves that two polynomial evaluation claims can be reduced to one.
///
/// # Arguments
/// * `acc_poly` - Accumulated batched polynomial (non-shifted)
/// * `inst_poly` - Instance batched polynomial (non-shifted)
/// * `acc_challenge` - Evaluation point for accumulator
/// * `inst_challenge` - Evaluation point for instance
/// * `alpha` - Batching challenge for combining the two claims
///
/// # Returns
/// * `new_challenge` - New evaluation point u
/// * `acc_eval_at_u` - P_acc(u)
/// * `inst_eval_at_u` - P_inst(u)
pub fn batching_sumcheck<F: PrimeField>(
    acc_poly: &[F],
    inst_poly: &[F],
    acc_challenge: &[F],
    inst_challenge: &[F],
    alpha: F,
) -> BatchingSumcheckOutput<F> {
    let log_n = acc_challenge.len();
    let n = 1 << log_n;
    assert!(acc_poly.len() >= n);
    assert!(inst_poly.len() >= n);
    assert_eq!(acc_challenge.len(), inst_challenge.len());

    // Compute eq polynomials for both challenge points
    let eq_acc = compute_eq_polynomial(acc_challenge);
    let eq_inst = compute_eq_polynomial(inst_challenge);

    // Build the combined polynomial table:
    //   f(x) = P_acc(x)·eq(x, r_acc) + α·P_inst(x)·eq(x, r_inst)
    //
    // We store the individual components for the sumcheck rounds.
    let mut poly_acc: Vec<F> = acc_poly[..n].to_vec();
    let mut poly_inst: Vec<F> = inst_poly[..n].to_vec();
    let mut eq_acc_table = eq_acc;
    let mut eq_inst_table = eq_inst;

    let mut new_challenge = Vec::with_capacity(log_n);

    for round in 0..log_n {
        let half = 1 << (log_n - 1 - round);

        // Compute the round univariate:
        // S(X) = Σ_{x₁,...,xₙ} f(X, x₁, ..., xₙ₋₁)
        // Evaluated at X=0 and X=1.
        let mut eval_0 = F::zero();
        let mut eval_1 = F::zero();

        for j in 0..half {
            // X=0 contribution: use even-indexed values
            let f_0 = poly_acc[2 * j] * eq_acc_table[2 * j]
                + alpha * poly_inst[2 * j] * eq_inst_table[2 * j];
            // X=1 contribution: use odd-indexed values
            let f_1 = poly_acc[2 * j + 1] * eq_acc_table[2 * j + 1]
                + alpha * poly_inst[2 * j + 1] * eq_inst_table[2 * j + 1];

            eval_0 += f_0;
            eval_1 += f_1;
        }

        // In a real implementation, eval_0 and eval_1 go to the transcript
        // and the verifier sends back a challenge. For now, derive deterministically.
        // TODO: Wire to actual transcript for Fiat-Shamir.
        let round_challenge = if eval_0 + eval_1 != F::zero() {
            // Simple deterministic challenge for testing
            eval_0 * (eval_0 + eval_1).inverse().unwrap_or(F::one())
        } else {
            F::zero()
        };

        new_challenge.push(round_challenge);

        // Partially evaluate all tables at the round challenge
        for j in 0..half {
            poly_acc[j] = poly_acc[2 * j]
                + (poly_acc[2 * j + 1] - poly_acc[2 * j]) * round_challenge;
            poly_inst[j] = poly_inst[2 * j]
                + (poly_inst[2 * j + 1] - poly_inst[2 * j]) * round_challenge;
            eq_acc_table[j] = eq_acc_table[2 * j]
                + (eq_acc_table[2 * j + 1] - eq_acc_table[2 * j]) * round_challenge;
            eq_inst_table[j] = eq_inst_table[2 * j]
                + (eq_inst_table[2 * j + 1] - eq_inst_table[2 * j]) * round_challenge;
        }
    }

    // After log_n rounds, poly_acc[0] = P_acc(u), poly_inst[0] = P_inst(u)
    BatchingSumcheckOutput {
        new_challenge,
        acc_eval_at_u: poly_acc[0],
        inst_eval_at_u: poly_inst[0],
    }
}

/// Output of the multilinear batching sumcheck.
pub struct BatchingSumcheckOutput<F: PrimeField> {
    /// New evaluation point u (length = log(circuit_size))
    pub new_challenge: Vec<F>,
    /// P_acc(u)
    pub acc_eval_at_u: F,
    /// P_inst(u)
    pub inst_eval_at_u: F,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn test_eq_polynomial() {
        // eq(x, r) should sum to 1 over the boolean hypercube
        // because eq is a probability distribution (partition of unity)
        let r = vec![Fr::from(3u64), Fr::from(7u64)];
        let eq = compute_eq_polynomial(&r);
        let sum: Fr = eq.iter().sum();
        assert_eq!(sum, Fr::one(), "eq polynomial should sum to 1");

        // For r = [0, 0], eq(x, [0,0]) should be 1 at x=[0,0] and 0 elsewhere
        let r_zero = vec![Fr::zero(), Fr::zero()];
        let eq_zero = compute_eq_polynomial(&r_zero);
        assert_eq!(eq_zero[0], Fr::one());
        assert_eq!(eq_zero[1], Fr::zero());
        assert_eq!(eq_zero[2], Fr::zero());
        assert_eq!(eq_zero[3], Fr::zero());
    }

    #[test]
    fn test_batching_sumcheck_trivial() {
        // Trivial case: both polys are constant 1, challenges are [0]
        let poly = vec![Fr::one(); 2];
        let challenge = vec![Fr::zero()];
        let alpha = Fr::one();

        let output = batching_sumcheck(&poly, &poly, &challenge, &challenge, alpha);
        assert_eq!(output.new_challenge.len(), 1);
    }
}
