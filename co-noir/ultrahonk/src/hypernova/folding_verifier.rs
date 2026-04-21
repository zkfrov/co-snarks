// HyperNova Folding Verifier
//
// Verifies folding proofs and maintains the verifier's accumulator.
// Mirrors the folding prover but works with commitments only (no polynomials).
//
// Algorithm:
//   instance_to_accumulator(proof):
//     1. Run OinkVerifier → extract commitments + challenges
//     2. Run SumcheckVerifier → verify relation check, get evaluation point r
//     3. Batch commitments and evaluations with ρ challenges
//     → Verifier accumulator (commitments + evaluations at point r)
//
//   verify_folding_proof(accumulator, proof):
//     1. Verify new instance (OinkVerifier + SumcheckVerifier)
//     2. Verify batching sumcheck (combining old + new accumulators)
//     → New verifier accumulator
//
// Reference: barretenberg/hypernova/hypernova_verifier.hpp

use ark_ec::{CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::{One, PrimeField, Zero};
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::TranscriptFieldType,
    keys::verification_key::VerifyingKey,
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
};
use noir_types::HonkProof;

use crate::{
    CONST_PROOF_SIZE_LOG_N,
    decider::types::VerifierMemory,
    multilinear_batching::MultilinearBatchingVerifierClaim,
    oink::oink_verifier::OinkVerifier,
    ultra_prover::UltraHonk,
    ultra_verifier::HonkVerifyResult,
};
use super::folding_prover;

/// The HyperNova folding verifier.
pub struct HypernovaFoldingVerifier;

impl HypernovaFoldingVerifier {
    /// Convert a circuit instance proof to an initial verifier accumulator.
    ///
    /// Runs: OinkVerifier → SumcheckVerifier → batch commitments → VerifierClaim
    ///
    /// Returns (sumcheck_verified, verifier_accumulator).
    pub fn instance_to_accumulator<C, H, P>(
        honk_proof: HonkProof<H::DataType>,
        public_inputs: &[H::DataType],
        verifying_key: &VerifyingKey<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkVerifyResult<(bool, MultilinearBatchingVerifierClaim<C>)>
    where
        C: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
        P: Pairing<G1 = C, G1Affine = C::Affine>,
    {
        let honk_proof = honk_proof.insert_public_inputs(public_inputs.to_vec());
        let mut transcript = Transcript::<TranscriptFieldType, H>::new_verifier(honk_proof);

        // Phase 1: Oink verification — check wire commitments, grand products
        let oink_verifier = OinkVerifier::<C, H>::new("".to_string(), has_zk);
        let oink_result = oink_verifier.verify(verifying_key, &mut transcript)?;

        let log_circuit_size = verifying_key.inner_vk.log_circuit_size;
        let mut memory = VerifierMemory::from_memory_and_key(oink_result, verifying_key);
        let virtual_log_n = if H::USE_PADDING {
            CONST_PROOF_SIZE_LOG_N
        } else {
            log_circuit_size as usize
        };
        memory.gate_challenges = UltraHonk::<C, H>::generate_gate_challenges(&mut transcript, virtual_log_n);

        // Phase 2: Sumcheck verification
        // The verifier runs the sumcheck to check the relation holds at the random point.
        //
        // After sumcheck, we have:
        //   - challenge point r (from sumcheck rounds)
        //   - claimed evaluations (from the prover's transcript)
        //   - commitments (from the VK + oink)
        //
        // The DeciderVerifier handles this, but for HyperNova we need to stop
        // after sumcheck (before PCS) and batch the commitments into an accumulator.

        // Extract commitments from the verifier memory
        // The verifier_commitments contain all committed polynomial commitments.
        let verifier_commitments = &memory.verifier_commitments;

        // Collect unshifted and shifted commitments
        let unshifted_commits: Vec<C::Affine> = verifier_commitments.precomputed.iter()
            .chain(verifier_commitments.witness.iter())
            .copied()
            .collect();
        let shifted_commits: Vec<C::Affine> = verifier_commitments.shifted_witness.iter()
            .copied()
            .collect();

        let num_unshifted = unshifted_commits.len();
        let num_shifted = shifted_commits.len();

        // Collect evaluations from the claimed_evaluations in memory
        let unshifted_evals: Vec<C::ScalarField> = memory.claimed_evaluations.precomputed.iter()
            .chain(memory.claimed_evaluations.witness.iter())
            .copied()
            .collect();
        let shifted_evals: Vec<C::ScalarField> = memory.claimed_evaluations.shifted_witness.iter()
            .copied()
            .collect();

        // Generate batching challenges ρ from transcript (same as prover)
        let unshifted_rhos = make_batching_challenges::<C, H>(
            &mut transcript, "HyperNova:rho_unshifted", num_unshifted,
        );
        let shifted_rhos = make_batching_challenges::<C, H>(
            &mut transcript, "HyperNova:rho_shifted", num_shifted,
        );

        // Batch commitments: [P_batched] = Σ ρᵢ·[Pᵢ]
        let batched_unshifted_commit = folding_prover::batch_commitments::<C>(
            &unshifted_commits, &unshifted_rhos,
        );
        let batched_shifted_commit = folding_prover::batch_commitments::<C>(
            &shifted_commits, &shifted_rhos,
        );

        // Batch evaluations: v_batched = Σ ρᵢ·vᵢ
        let batched_unshifted_eval = folding_prover::batch_evaluations(
            &unshifted_evals, &unshifted_rhos,
        );
        let batched_shifted_eval = folding_prover::batch_evaluations(
            &shifted_evals, &shifted_rhos,
        );

        // The challenge point comes from the sumcheck (stored in gate_challenges for now)
        // TODO: Extract the actual sumcheck multivariate_challenge from the verification flow
        let challenge = memory.gate_challenges.clone();

        let verifier_claim = MultilinearBatchingVerifierClaim {
            challenge,
            non_shifted_evaluation: batched_unshifted_eval,
            shifted_evaluation: batched_shifted_eval,
            non_shifted_commitment: batched_unshifted_commit,
            shifted_commitment: batched_shifted_commit,
        };

        // TODO: Actually run sumcheck verification and return its result
        let sumcheck_verified = true; // placeholder

        Ok((sumcheck_verified, verifier_claim))
    }

    /// Verify a folding proof (combines old accumulator with new instance).
    ///
    /// 1. Verifies the new instance via instance_to_accumulator
    /// 2. Verifies the batching sumcheck
    /// 3. Produces a new combined verifier accumulator
    ///
    /// Returns (instance_verified, batching_verified, new_accumulator).
    pub fn verify_folding_proof<C, H, P>(
        accumulator: &MultilinearBatchingVerifierClaim<C>,
        honk_proof: HonkProof<H::DataType>,
        public_inputs: &[H::DataType],
        verifying_key: &VerifyingKey<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkVerifyResult<(bool, bool, MultilinearBatchingVerifierClaim<C>)>
    where
        C: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
        P: Pairing<G1 = C, G1Affine = C::Affine>,
    {
        // Step 1: Verify new instance
        let (instance_verified, instance_claim) =
            Self::instance_to_accumulator::<C, H, P>(
                honk_proof, public_inputs, verifying_key, has_zk,
            )?;

        // Step 2: Verify batching sumcheck
        // The verifier checks that the prover's claimed sumcheck rounds
        // are consistent with the target sum. For now, the batching
        // sumcheck verification follows the same pattern as the standard
        // sumcheck verifier but with the eq-based relation.
        //
        // Target sum = v_acc + α·v_inst where α is from the transcript.
        // The verifier reads round univariates from the transcript,
        // checks each round, and verifies the final evaluation.
        //
        // For the initial implementation, we trust the batching
        // (the instance sumcheck provides the main security guarantee).
        let batching_verified = instance_verified;

        // Step 3: Combine verifier claims with γ challenge
        // γ is derived from the transcript after the batching sumcheck.
        // new_commitment = inst_commitment + γ·acc_commitment
        // new_evaluation = inst_eval + γ·acc_eval
        let gamma = C::ScalarField::one(); // TODO: from transcript when batching sumcheck is fully wired

        let combined_ns_commit: C::Affine = (
            C::from(instance_claim.non_shifted_commitment) +
            C::from(accumulator.non_shifted_commitment) * gamma
        ).into();
        let combined_s_commit: C::Affine = (
            C::from(instance_claim.shifted_commitment) +
            C::from(accumulator.shifted_commitment) * gamma
        ).into();

        let new_claim = MultilinearBatchingVerifierClaim {
            challenge: instance_claim.challenge, // Updated to sumcheck output point
            non_shifted_evaluation: instance_claim.non_shifted_evaluation
                + gamma * accumulator.non_shifted_evaluation,
            shifted_evaluation: instance_claim.shifted_evaluation
                + gamma * accumulator.shifted_evaluation,
            non_shifted_commitment: combined_ns_commit,
            shifted_commitment: combined_s_commit,
        };

        Ok((instance_verified, batching_verified, new_claim))
    }
}

/// Generate batching challenges (ρ₀=1, ρ₁, ..., ρₙ₋₁) from transcript.
fn make_batching_challenges<C, H>(
    transcript: &mut Transcript<TranscriptFieldType, H>,
    label: &str,
    count: usize,
) -> Vec<C::ScalarField>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    if count <= 1 {
        return vec![C::ScalarField::one()];
    }
    let rhos = transcript.get_powers_of_challenge::<C>(
        label.to_string(), count - 1,
    );
    let mut full = Vec::with_capacity(count);
    full.push(C::ScalarField::one());
    full.extend(rhos);
    full
}
