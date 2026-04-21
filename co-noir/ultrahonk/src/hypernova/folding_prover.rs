// HyperNova Folding Prover
//
// Orchestrates: OinkProver → SumcheckProver → batch → Accumulator
//
// This module provides:
//   - Polynomial/commitment/evaluation batching functions
//   - sumcheck_output_to_accumulator: converts Oink+Sumcheck output to accumulator
//   - combine_accumulators: merges two accumulators with γ challenge
//   - HypernovaFoldingProver: top-level orchestrator
//
// Reference: barretenberg/hypernova/hypernova_prover.hpp

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    keys::{plain_proving_key::PlainProvingKey, verification_key::VerifyingKeyBarretenberg},
    polynomials::polynomial::Polynomial,
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
};
use crate::{
    CONST_PROOF_SIZE_LOG_N,
    decider::types::ProverMemory,
    multilinear_batching::MultilinearBatchingProverClaim,
    oink::oink_prover::Oink,
    ultra_prover::UltraHonk,
};

// ─── Batching Functions ───

/// Batch a collection of polynomials with scalar challenges.
/// P_batched = Σ ρᵢ·Pᵢ
pub fn batch_polynomials<F: PrimeField>(
    polynomials: &[&[F]],
    challenges: &[F],
) -> Vec<F> {
    assert!(!polynomials.is_empty());
    assert_eq!(polynomials.len(), challenges.len());

    let max_size = polynomials.iter().map(|p| p.len()).max().unwrap_or(0);
    let mut batched = vec![F::zero(); max_size];

    for (poly, &rho) in polynomials.iter().zip(challenges.iter()) {
        for j in 0..poly.len() {
            batched[j] += rho * poly[j];
        }
    }
    batched
}

/// Batch scalar evaluations: v_batched = Σ ρᵢ·vᵢ
pub fn batch_evaluations<F: PrimeField>(evaluations: &[F], challenges: &[F]) -> F {
    evaluations
        .iter()
        .zip(challenges.iter())
        .fold(F::zero(), |acc, (&v, &rho)| acc + rho * v)
}

/// Batch commitments via MSM: [P_batched] = Σ ρᵢ·[Pᵢ]
pub fn batch_commitments<P: CurveGroup>(
    commitments: &[P::Affine],
    challenges: &[P::ScalarField],
) -> P::Affine {
    if commitments.is_empty() {
        return P::Affine::default();
    }
    P::msm_unchecked(commitments, challenges).into()
}

// ─── Accumulator Construction ───

/// Convert sumcheck output into a MultilinearBatchingProverClaim.
///
/// After Oink + Sumcheck, we have evaluations of all polynomials at a random
/// point r. This function batches them into a single polynomial claim using
/// ρ challenges from the transcript.
pub fn sumcheck_output_to_accumulator<P: CurveGroup>(
    challenge: Vec<P::ScalarField>,
    unshifted_polynomials: &[&[P::ScalarField]],
    shifted_polynomials: &[&[P::ScalarField]],
    unshifted_evaluations: &[P::ScalarField],
    shifted_evaluations: &[P::ScalarField],
    unshifted_commitments: &[P::Affine],
    shifted_commitments: &[P::Affine],
    unshifted_challenges: &[P::ScalarField],
    shifted_challenges: &[P::ScalarField],
    circuit_size: usize,
) -> MultilinearBatchingProverClaim<P> {
    let batched_unshifted_poly = batch_polynomials(unshifted_polynomials, unshifted_challenges);
    let batched_unshifted_eval = batch_evaluations(unshifted_evaluations, unshifted_challenges);
    let batched_unshifted_commit = batch_commitments::<P>(unshifted_commitments, unshifted_challenges);

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

/// Combine two accumulators: P_new = P_inst + γ·P_acc
pub fn combine_accumulators<P: CurveGroup>(
    accumulator: &MultilinearBatchingProverClaim<P>,
    instance: &MultilinearBatchingProverClaim<P>,
    new_challenge: Vec<P::ScalarField>,
    gamma: P::ScalarField,
    acc_eval_at_u: (P::ScalarField, P::ScalarField),
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
    let combined_ns: P::Affine = (P::from(instance.non_shifted_commitment) +
        P::from(accumulator.non_shifted_commitment) * gamma).into();
    let combined_s: P::Affine = (P::from(instance.shifted_commitment) +
        P::from(accumulator.shifted_commitment) * gamma).into();

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

// ─── HyperNova Folding Prover ───

/// Top-level HyperNova folding prover.
///
/// Orchestrates the full pipeline: Oink → Sumcheck → batch → Accumulator.
/// For folding, runs the pipeline on the new instance and then combines
/// with the existing accumulator via MultilinearBatching sumcheck.
pub struct HypernovaFoldingProver;

impl HypernovaFoldingProver {
    /// Convert a circuit instance to an initial accumulator.
    ///
    /// Runs: Oink → Sumcheck → batch polynomials/commitments → Accumulator
    ///
    /// This is the UltraHonk prover flow minus the PCS (Shplemini+KZG),
    /// plus the batching step that combines all polynomials into one claim.
    pub fn instance_to_accumulator<C, H>(
        mut proving_key: PlainProvingKey<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> HonkProofResult<(MultilinearBatchingProverClaim<C>, Transcript<TranscriptFieldType, H>)>
    where
        C: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
    {
        let mut transcript = Transcript::<TranscriptFieldType, H>::new();

        // Phase 1: Oink — compute wire commitments, grand products, challenges
        let oink = Oink::new(has_zk);
        let oink_result = oink.prove(&mut proving_key, &mut transcript, verifying_key)?;

        let circuit_size = proving_key.circuit_size;
        let mut memory =
            ProverMemory::from_memory_and_polynomials(oink_result, proving_key.polynomials);
        let log_dyadic_circuit_size = circuit_size.next_power_of_two().ilog2() as usize;
        let virtual_log_n = if H::USE_PADDING {
            CONST_PROOF_SIZE_LOG_N
        } else {
            log_dyadic_circuit_size
        };
        memory.gate_challenges = UltraHonk::<C, H>::generate_gate_challenges(&mut transcript, virtual_log_n);

        // Phase 2: Sumcheck — evaluate all relations at random point r
        // The sumcheck is run inside the Decider. For HyperNova we need
        // the intermediate state (evaluations + polynomials), not the final PCS.
        //
        // TODO: Extract sumcheck-only path from Decider to avoid duplicating.
        // For now, we document the connection point.
        //
        // After sumcheck:
        //   - challenges = evaluation point r
        //   - evaluations = AllEntities<F> of all polys at r
        //   - memory.polys = the actual polynomials (for batching)
        //
        // Phase 3: Batch — combine all polys/commitments/evals with ρ challenges
        //
        // The batching uses get_batching_challenges from the transcript to get
        // per-polynomial ρ values, then calls sumcheck_output_to_accumulator.

        // Phase 2: Sumcheck — evaluate all relations at random point r
        let decider = crate::decider::decider_prover::Decider::<C, H>::new(
            memory, has_zk,
        );
        let sumcheck_output = decider.sumcheck_prove(
            &mut transcript, circuit_size, virtual_log_n,
        );

        let claimed_evaluations = sumcheck_output.claimed_evaluations
            .expect("sumcheck_prove now always captures evaluations");

        // Phase 3: Batch all polynomials/commitments/evaluations into accumulator
        //
        // The polynomials and evaluations are in AllEntities which has:
        //   .witness (unshifted witness polys)
        //   .precomputed (unshifted precomputed polys)
        //   .shifted_witness (shifted witness polys)
        //
        // For batching we need separate unshifted and shifted arrays.
        // Unshifted = precomputed + witness, Shifted = shifted_witness.

        // Collect unshifted polynomials (Vec<F>) and evaluations (F)
        // Unshifted = precomputed + witness entities
        // polys are AllEntities<Vec<F>>, evals are AllEntities<F>
        let unshifted_polys: Vec<&[C::ScalarField]> = decider.memory.polys.precomputed.iter()
            .map(|p: &Vec<C::ScalarField>| p.as_slice())
            .chain(decider.memory.polys.witness.iter().map(|p: &Vec<C::ScalarField>| p.as_slice()))
            .collect();
        let unshifted_evals: Vec<C::ScalarField> = claimed_evaluations.precomputed.iter()
            .copied()
            .chain(claimed_evaluations.witness.iter().copied())
            .collect();

        // Collect shifted polynomials and evaluations
        let shifted_polys: Vec<&[C::ScalarField]> = decider.memory.polys.shifted_witness.iter()
            .map(|p: &Vec<C::ScalarField>| p.as_slice())
            .collect();
        let shifted_evals: Vec<C::ScalarField> = claimed_evaluations.shifted_witness.iter()
            .copied()
            .collect();

        let num_unshifted = unshifted_polys.len();
        let num_shifted = shifted_polys.len();

        // Generate batching challenges ρ from transcript
        // First coefficient is implicit 1, rest are random from transcript
        let unshifted_rhos: Vec<C::ScalarField> = if num_unshifted > 1 {
            let rhos = transcript.get_powers_of_challenge::<C>(
                "HyperNova:rho_unshifted".to_string(),
                num_unshifted - 1,
            );
            let mut full = Vec::with_capacity(num_unshifted);
            full.push(C::ScalarField::one());
            full.extend(rhos);
            full
        } else {
            vec![C::ScalarField::one()]
        };

        let shifted_rhos: Vec<C::ScalarField> = if num_shifted > 1 {
            let rhos = transcript.get_powers_of_challenge::<C>(
                "HyperNova:rho_shifted".to_string(),
                num_shifted - 1,
            );
            let mut full = Vec::with_capacity(num_shifted);
            full.push(C::ScalarField::one());
            full.extend(rhos);
            full
        } else {
            vec![C::ScalarField::one()]
        };

        // TODO: Extract commitments from VerificationKey.
        // For now, use empty commitment arrays (the batching math is correct,
        // but we need the VK's commitment points to produce a valid accumulator).
        let unshifted_commits: Vec<C::Affine> = vec![C::Affine::default(); num_unshifted];
        let shifted_commits: Vec<C::Affine> = vec![C::Affine::default(); num_shifted];

        let dyadic_size = (circuit_size as usize).next_power_of_two();
        let accumulator = sumcheck_output_to_accumulator::<C>(
            sumcheck_output.challenges,
            &unshifted_polys,
            &shifted_polys,
            &unshifted_evals,
            &shifted_evals,
            &unshifted_commits,
            &shifted_commits,
            &unshifted_rhos,
            &shifted_rhos,
            dyadic_size,
        );

        Ok((accumulator, transcript))
    }
}
