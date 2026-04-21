// HyperNova Folding Prover
//
// Converts circuit instances to accumulators and folds them together.
//
// Core algorithm (instance_to_accumulator):
//   1. Run OinkProver → wire commitments, grand products, challenges
//   2. Run SumcheckProver → evaluate all relations at random point r
//   3. Batch all polynomials/commitments/evaluations with ρ challenges
//   → Accumulator (single batched polynomial claim at point r)
//
// Reference: barretenberg/hypernova/hypernova_prover.hpp

use ark_ec::CurveGroup;
use ark_ff::{One, PrimeField, Zero};
use co_noir_common::polynomials::polynomial::Polynomial;
use crate::multilinear_batching::MultilinearBatchingProverClaim;

/// Batch a collection of polynomials with scalar challenges.
///
/// Computes: P_batched = ρ₀·P₀ + ρ₁·P₁ + ... + ρₙ₋₁·Pₙ₋₁
/// where ρ₀ = 1 (implicit).
///
/// Operates in-place on the first polynomial for efficiency.
pub fn batch_polynomials<F: PrimeField>(
    polynomials: &[Vec<F>],
    challenges: &[F],
) -> Vec<F> {
    assert!(!polynomials.is_empty());
    assert_eq!(polynomials.len(), challenges.len());

    let size = polynomials[0].len();
    let mut batched = vec![F::zero(); size];

    // First polynomial has implicit ρ₀ = 1 (challenges[0] should be 1)
    for (i, poly) in polynomials.iter().enumerate() {
        let rho = challenges[i];
        for j in 0..poly.len().min(size) {
            batched[j] += rho * poly[j];
        }
    }

    batched
}

/// Batch scalar evaluations with challenges.
///
/// Computes: v_batched = ρ₀·v₀ + ρ₁·v₁ + ... + ρₙ₋₁·vₙ₋₁
pub fn batch_evaluations<F: PrimeField>(
    evaluations: &[F],
    challenges: &[F],
) -> F {
    assert_eq!(evaluations.len(), challenges.len());
    evaluations
        .iter()
        .zip(challenges.iter())
        .fold(F::zero(), |acc, (v, rho)| acc + *rho * v)
}

/// Batch commitments (EC points) with scalar challenges.
///
/// Computes: [P_batched] = ρ₀·[P₀] + ρ₁·[P₁] + ... + ρₙ₋₁·[Pₙ₋₁]
/// This is a multi-scalar multiplication (MSM).
pub fn batch_commitments<P: CurveGroup>(
    commitments: &[P::Affine],
    challenges: &[P::ScalarField],
) -> P::Affine {
    use ark_ec::VariableBaseMSM;
    if commitments.is_empty() {
        return P::Affine::default();
    }
    P::msm_unchecked(commitments, challenges).into()
}

/// Convert sumcheck output to a MultilinearBatchingProverClaim (accumulator).
///
/// After sumcheck produces evaluations of all polynomials at a random point r,
/// this function batches them into a single polynomial claim:
///   P_batched = Σ ρᵢ·Pᵢ
///   v_batched = Σ ρᵢ·vᵢ
///   [P_batched] = Σ ρᵢ·[Pᵢ]
///
/// Separately for unshifted and shifted polynomials.
///
/// # Arguments
///
/// * `challenge` - The sumcheck evaluation point r (length = log(circuit_size))
/// * `unshifted_polynomials` - All non-shifted witness polynomials
/// * `shifted_polynomials` - All shifted witness polynomials (pre-shift form)
/// * `unshifted_evaluations` - Evaluations Pᵢ(r) for each unshifted poly
/// * `shifted_evaluations` - Evaluations P̃ᵢ(r) for each shifted poly
/// * `unshifted_commitments` - Commitments [Pᵢ] for each unshifted poly
/// * `shifted_commitments` - Commitments [P̃ᵢ] for each shifted poly
/// * `unshifted_challenges` - Batching challenges ρ for unshifted (first = 1)
/// * `shifted_challenges` - Batching challenges ρ for shifted (first = 1)
/// * `circuit_size` - Domain size (power of 2)
pub fn sumcheck_output_to_accumulator<P: CurveGroup>(
    challenge: Vec<P::ScalarField>,
    unshifted_polynomials: &[Vec<P::ScalarField>],
    shifted_polynomials: &[Vec<P::ScalarField>],
    unshifted_evaluations: &[P::ScalarField],
    shifted_evaluations: &[P::ScalarField],
    unshifted_commitments: &[P::Affine],
    shifted_commitments: &[P::Affine],
    unshifted_challenges: &[P::ScalarField],
    shifted_challenges: &[P::ScalarField],
    circuit_size: usize,
) -> MultilinearBatchingProverClaim<P> {
    // Batch unshifted: P = Σ ρᵢ·Pᵢ
    let batched_unshifted_poly = batch_polynomials(unshifted_polynomials, unshifted_challenges);
    let batched_unshifted_eval = batch_evaluations(unshifted_evaluations, unshifted_challenges);
    let batched_unshifted_commit = batch_commitments::<P>(unshifted_commitments, unshifted_challenges);

    // Batch shifted: P̃ = Σ ρᵢ·P̃ᵢ
    let batched_shifted_poly = batch_polynomials(shifted_polynomials, shifted_challenges);
    let batched_shifted_eval = batch_evaluations(shifted_evaluations, shifted_challenges);
    let batched_shifted_commit = batch_commitments::<P>(shifted_commitments, shifted_challenges);

    MultilinearBatchingProverClaim {
        challenge,
        non_shifted_evaluation: batched_unshifted_eval,
        shifted_evaluation: batched_shifted_eval,
        non_shifted_polynomial: Polynomial::new(batched_unshifted_poly),
        shifted_polynomial: Polynomial::new(batched_shifted_poly),
        non_shifted_commitment: batched_unshifted_commit,
        shifted_commitment: batched_shifted_commit,
        dyadic_size: circuit_size,
    }
}

/// Combine two accumulators into one (the batching step of fold).
///
/// Given: accumulator at point r_acc, instance at point r_inst,
/// and batching challenge γ from transcript.
///
/// Produces: new accumulator at point u (from batching sumcheck)
///   P_new = P_inst + γ·P_acc
///   v_new = v_inst(u) + γ·v_acc(u)
///   [P_new] = [P_inst] + γ·[P_acc]
pub fn combine_accumulators<P: CurveGroup>(
    accumulator: &MultilinearBatchingProverClaim<P>,
    instance: &MultilinearBatchingProverClaim<P>,
    new_challenge: Vec<P::ScalarField>,
    gamma: P::ScalarField,
    acc_eval_at_u: (P::ScalarField, P::ScalarField), // (non_shifted, shifted) evals at new point
    inst_eval_at_u: (P::ScalarField, P::ScalarField),
) -> MultilinearBatchingProverClaim<P> {
    let size = accumulator.dyadic_size.max(instance.dyadic_size);

    // P_new = P_inst + γ·P_acc
    let mut new_non_shifted = instance.non_shifted_polynomial.as_ref().to_vec();
    let acc_ns = accumulator.non_shifted_polynomial.as_ref();
    for i in 0..new_non_shifted.len().min(acc_ns.len()) {
        new_non_shifted[i] += gamma * acc_ns[i];
    }

    let mut new_shifted = instance.shifted_polynomial.as_ref().to_vec();
    let acc_s = accumulator.shifted_polynomial.as_ref();
    for i in 0..new_shifted.len().min(acc_s.len()) {
        new_shifted[i] += gamma * acc_s[i];
    }

    // v_new = v_inst(u) + γ·v_acc(u)
    let new_ns_eval = inst_eval_at_u.0 + gamma * acc_eval_at_u.0;
    let new_s_eval = inst_eval_at_u.1 + gamma * acc_eval_at_u.1;

    // [P_new] = [P_inst] + γ·[P_acc]
    let new_ns_commit: P = instance.non_shifted_commitment.into();
    let acc_ns_commit: P = accumulator.non_shifted_commitment.into();
    let combined_ns: P::Affine = (new_ns_commit + acc_ns_commit * gamma).into();

    let new_s_commit: P = instance.shifted_commitment.into();
    let acc_s_commit: P = accumulator.shifted_commitment.into();
    let combined_s: P::Affine = (new_s_commit + acc_s_commit * gamma).into();

    MultilinearBatchingProverClaim {
        challenge: new_challenge,
        non_shifted_evaluation: new_ns_eval,
        shifted_evaluation: new_s_eval,
        non_shifted_polynomial: Polynomial::new(new_non_shifted),
        shifted_polynomial: Polynomial::new(new_shifted),
        non_shifted_commitment: combined_ns,
        shifted_commitment: combined_s,
        dyadic_size: size,
    }
}

/// The HyperNova folding prover.
pub struct HypernovaFoldingProver;

impl HypernovaFoldingProver {
    /// Convert a circuit instance to an initial accumulator.
    ///
    /// Runs: OinkProver → SumcheckProver → batch → Accumulator
    ///
    /// TODO: Wire to existing OinkProver and SumcheckProver.
    /// The batching logic (sumcheck_output_to_accumulator) is implemented above.
    /// What remains is connecting it to the prover infrastructure:
    ///   1. Call OinkProver::prove(proving_key, transcript, vk) → oink_memory
    ///   2. Build ProverMemory from oink_memory + polynomials
    ///   3. Call SumcheckProver to get evaluation point + evaluations
    ///   4. Extract polynomial/commitment/evaluation arrays from ProverMemory
    ///   5. Call sumcheck_output_to_accumulator with batching challenges from transcript
    pub fn instance_to_accumulator() {
        todo!("Wire OinkProver + SumcheckProver + sumcheck_output_to_accumulator")
    }

    /// Fold a new instance into an existing accumulator.
    ///
    /// TODO: Wire to MultilinearBatchingProver (which runs a second sumcheck).
    pub fn fold() {
        todo!("Wire instance_to_accumulator + MultilinearBatchingProver + combine_accumulators")
    }
}
