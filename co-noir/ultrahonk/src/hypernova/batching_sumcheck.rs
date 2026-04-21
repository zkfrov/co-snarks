// Multilinear Batching Sumcheck
//
// Reduces two polynomial evaluation claims to one via sumcheck.
// Uses Fiat-Shamir transcript for challenge derivation (matching bb).
//
// The relation: Σ_x [ P_acc(x)·eq(x, r_acc) + α·P_inst(x)·eq(x, r_inst) ] = v_acc + α·v_inst
//
// Reference: barretenberg/multilinear_batching/

use ark_ff::{One, PrimeField, Zero};
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::TranscriptFieldType,
    transcript::{Transcript, TranscriptHasher},
};

/// Compute the multilinear equality polynomial eq(x, r) for all x ∈ {0,1}^n.
pub fn compute_eq_polynomial<F: PrimeField>(r: &[F]) -> Vec<F> {
    let n = r.len();
    let size = 1 << n;
    let mut eq = vec![F::zero(); size];
    eq[0] = F::one();

    for (i, &r_i) in r.iter().enumerate() {
        let half = 1 << i;
        for j in (0..half).rev() {
            eq[2 * j + 1] = eq[j] * r_i;
            eq[2 * j] = eq[j] * (F::one() - r_i);
        }
    }
    eq
}

/// Run the multilinear batching sumcheck with Fiat-Shamir transcript.
///
/// Handles BOTH non-shifted and shifted polynomial pairs.
///
/// # Arguments
/// * `acc_unshifted` / `acc_shifted` - Accumulator's batched polynomials
/// * `inst_unshifted` / `inst_shifted` - Instance's batched polynomials
/// * `acc_challenge` - Evaluation point for accumulator
/// * `inst_challenge` - Evaluation point for instance
/// * `alpha` - Challenge for combining the two claims
/// * `transcript` - Fiat-Shamir transcript for round challenges
pub fn batching_sumcheck<C, H>(
    acc_unshifted: &[C::ScalarField],
    acc_shifted: &[C::ScalarField],
    inst_unshifted: &[C::ScalarField],
    inst_shifted: &[C::ScalarField],
    acc_challenge: &[C::ScalarField],
    inst_challenge: &[C::ScalarField],
    alpha: C::ScalarField,
    transcript: &mut Transcript<TranscriptFieldType, H>,
) -> BatchingSumcheckOutput<C::ScalarField>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    let log_n = acc_challenge.len();
    let n = 1 << log_n;
    assert_eq!(acc_challenge.len(), inst_challenge.len());

    // Compute eq polynomials
    let eq_acc = compute_eq_polynomial(acc_challenge);
    let eq_inst = compute_eq_polynomial(inst_challenge);

    // Working tables for partial evaluation
    let mut p_acc_ns: Vec<C::ScalarField> = pad_to(acc_unshifted, n);
    let mut p_acc_s: Vec<C::ScalarField> = pad_to(acc_shifted, n);
    let mut p_inst_ns: Vec<C::ScalarField> = pad_to(inst_unshifted, n);
    let mut p_inst_s: Vec<C::ScalarField> = pad_to(inst_shifted, n);
    let mut eq_acc_table = eq_acc;
    let mut eq_inst_table = eq_inst;

    let mut new_challenge = Vec::with_capacity(log_n);

    for round in 0..log_n {
        let half = 1 << (log_n - 1 - round);

        // Compute round univariate S(X) evaluated at X=0 and X=1
        let mut eval_0 = C::ScalarField::zero();
        let mut eval_1 = C::ScalarField::zero();

        for j in 0..half {
            // Non-shifted contributions
            let ns_0 = p_acc_ns[2 * j] * eq_acc_table[2 * j]
                + alpha * p_inst_ns[2 * j] * eq_inst_table[2 * j];
            let ns_1 = p_acc_ns[2 * j + 1] * eq_acc_table[2 * j + 1]
                + alpha * p_inst_ns[2 * j + 1] * eq_inst_table[2 * j + 1];

            // Shifted contributions (same eq polynomials, different data polys)
            let s_0 = p_acc_s[2 * j] * eq_acc_table[2 * j]
                + alpha * p_inst_s[2 * j] * eq_inst_table[2 * j];
            let s_1 = p_acc_s[2 * j + 1] * eq_acc_table[2 * j + 1]
                + alpha * p_inst_s[2 * j + 1] * eq_inst_table[2 * j + 1];

            eval_0 += ns_0 + s_0;
            eval_1 += ns_1 + s_1;
        }

        // Fiat-Shamir: send evaluations to transcript, get challenge back
        transcript.send_fr_to_verifier::<C>(
            format!("BatchingSumcheck:univariate_{round}_0"), eval_0,
        );
        transcript.send_fr_to_verifier::<C>(
            format!("BatchingSumcheck:univariate_{round}_1"), eval_1,
        );
        let round_challenge = transcript.get_challenge::<C>(
            format!("BatchingSumcheck:u_{round}"),
        );
        new_challenge.push(round_challenge);

        // Partially evaluate all tables at the round challenge
        for j in 0..half {
            p_acc_ns[j] = p_acc_ns[2 * j]
                + (p_acc_ns[2 * j + 1] - p_acc_ns[2 * j]) * round_challenge;
            p_acc_s[j] = p_acc_s[2 * j]
                + (p_acc_s[2 * j + 1] - p_acc_s[2 * j]) * round_challenge;
            p_inst_ns[j] = p_inst_ns[2 * j]
                + (p_inst_ns[2 * j + 1] - p_inst_ns[2 * j]) * round_challenge;
            p_inst_s[j] = p_inst_s[2 * j]
                + (p_inst_s[2 * j + 1] - p_inst_s[2 * j]) * round_challenge;
            eq_acc_table[j] = eq_acc_table[2 * j]
                + (eq_acc_table[2 * j + 1] - eq_acc_table[2 * j]) * round_challenge;
            eq_inst_table[j] = eq_inst_table[2 * j]
                + (eq_inst_table[2 * j + 1] - eq_inst_table[2 * j]) * round_challenge;
        }
    }

    // After log_n rounds, each table has been reduced to a single value
    BatchingSumcheckOutput {
        new_challenge,
        acc_ns_eval_at_u: p_acc_ns[0],
        acc_s_eval_at_u: p_acc_s[0],
        inst_ns_eval_at_u: p_inst_ns[0],
        inst_s_eval_at_u: p_inst_s[0],
    }
}

/// Verify the batching sumcheck (verifier side).
///
/// Reads round univariates from transcript, checks consistency,
/// derives the same challenges as the prover.
pub fn verify_batching_sumcheck<C, H>(
    acc_ns_eval: C::ScalarField,
    acc_s_eval: C::ScalarField,
    inst_ns_eval: C::ScalarField,
    inst_s_eval: C::ScalarField,
    alpha: C::ScalarField,
    log_n: usize,
    transcript: &mut Transcript<TranscriptFieldType, H>,
) -> (bool, Vec<C::ScalarField>)
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    // Target sum: v_acc_ns + v_acc_s + α·(v_inst_ns + v_inst_s)
    let target_sum = (acc_ns_eval + acc_s_eval)
        + alpha * (inst_ns_eval + inst_s_eval);

    let mut running_sum = target_sum;
    let mut new_challenge = Vec::with_capacity(log_n);
    let mut verified = true;

    for round in 0..log_n {
        // Read prover's claimed evaluations at X=0 and X=1
        let eval_0 = transcript.receive_fr_from_prover::<C>(
            format!("BatchingSumcheck:univariate_{round}_0"),
        ).unwrap_or_default();
        let eval_1 = transcript.receive_fr_from_prover::<C>(
            format!("BatchingSumcheck:univariate_{round}_1"),
        ).unwrap_or_default();

        // Check: S(0) + S(1) should equal the running sum
        if eval_0 + eval_1 != running_sum {
            verified = false;
        }

        // Derive challenge (same as prover via Fiat-Shamir)
        let round_challenge = transcript.get_challenge::<C>(
            format!("BatchingSumcheck:u_{round}"),
        );
        new_challenge.push(round_challenge);

        // Update running sum: S_{next} = S(u_i) = (1-u_i)·S(0) + u_i·S(1)
        running_sum = eval_0 + round_challenge * (eval_1 - eval_0);
    }

    (verified, new_challenge)
}

/// Output of the multilinear batching sumcheck.
pub struct BatchingSumcheckOutput<F: PrimeField> {
    pub new_challenge: Vec<F>,
    pub acc_ns_eval_at_u: F,
    pub acc_s_eval_at_u: F,
    pub inst_ns_eval_at_u: F,
    pub inst_s_eval_at_u: F,
}

/// Pad a slice to length n with zeros.
fn pad_to<F: PrimeField>(slice: &[F], n: usize) -> Vec<F> {
    let mut v = vec![F::zero(); n];
    let copy_len = slice.len().min(n);
    v[..copy_len].copy_from_slice(&slice[..copy_len]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn test_eq_polynomial_sum() {
        let r = vec![Fr::from(3u64), Fr::from(7u64)];
        let eq = compute_eq_polynomial(&r);
        let sum: Fr = eq.iter().sum();
        assert_eq!(sum, Fr::one(), "eq polynomial should sum to 1");
    }

    #[test]
    fn test_eq_polynomial_delta() {
        let r_zero = vec![Fr::zero(), Fr::zero()];
        let eq_zero = compute_eq_polynomial(&r_zero);
        assert_eq!(eq_zero[0], Fr::one());
        assert_eq!(eq_zero[1], Fr::zero());
        assert_eq!(eq_zero[2], Fr::zero());
        assert_eq!(eq_zero[3], Fr::zero());
    }
}
