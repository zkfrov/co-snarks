// HyperNova Folding Verifier
//
// Runs OinkVerifier + SumcheckVerifier (actual verification, not placeholder)
// then batches commitments into a verifier accumulator.
//
// Reference: barretenberg/hypernova/hypernova_verifier.hpp

use ark_ec::{CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::{One, PrimeField, Zero};
use co_noir_common::{
    constants::BATCHED_RELATION_PARTIAL_LENGTH,
    honk_curve::HonkCurve,
    honk_proof::TranscriptFieldType,
    keys::verification_key::VerifyingKey,
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
};
use noir_types::HonkProof;

use crate::{
    CONST_PROOF_SIZE_LOG_N,
    decider::{
        decider_verifier::DeciderVerifier,
        types::VerifierMemory,
    },
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
    /// Runs the ACTUAL sumcheck verification (not a placeholder), then batches
    /// commitments and evaluations into a verifier accumulator.
    ///
    /// Returns (sumcheck_verified, verifier_accumulator, transcript) — transcript
    /// is returned for chaining into verify_folding_proof.
    pub fn instance_to_accumulator<C, H, P>(
        honk_proof: HonkProof<H::DataType>,
        public_inputs: &[H::DataType],
        verifying_key: &VerifyingKey<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkVerifyResult<(bool, MultilinearBatchingVerifierClaim<C>, Transcript<TranscriptFieldType, H>)>
    where
        C: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
        P: Pairing<G1 = C, G1Affine = C::Affine>,
    {
        let honk_proof = honk_proof.insert_public_inputs(public_inputs.to_vec());
        let mut transcript = Transcript::<TranscriptFieldType, H>::new_verifier(honk_proof);

        // Phase 1: Oink verification
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

        // Phase 2: ACTUAL sumcheck verification
        // Build a DeciderVerifier and run sumcheck_verify to get:
        //   - multivariate_challenge (the evaluation point r)
        //   - verified (did the sumcheck pass?)
        //   - claimed_evaluations populated in memory
        let padding_indicator_array = vec![C::ScalarField::one(); virtual_log_n];
        let mut decider_verifier = DeciderVerifier::<C, H>::new(memory);
        let sumcheck_output = decider_verifier.sumcheck_verify::<BATCHED_RELATION_PARTIAL_LENGTH>(
            &mut transcript,
            has_zk,
            &padding_indicator_array,
        )?;

        let sumcheck_verified = sumcheck_output.verified;
        let multivariate_challenge = sumcheck_output.multivariate_challenge;

        // Extract memory back from DeciderVerifier for commitments/evaluations
        let memory = decider_verifier.into_memory();

        // Phase 3: Batch commitments and evaluations
        let verifier_commitments = &memory.verifier_commitments;

        let unshifted_commits: Vec<C::Affine> = verifier_commitments.precomputed.iter()
            .chain(verifier_commitments.witness.iter())
            .copied()
            .collect();
        let shifted_commits: Vec<C::Affine> = verifier_commitments.shifted_witness.iter()
            .copied()
            .collect();

        let num_unshifted = unshifted_commits.len();
        let num_shifted = shifted_commits.len();

        let unshifted_evals: Vec<C::ScalarField> = memory.claimed_evaluations.precomputed.iter()
            .chain(memory.claimed_evaluations.witness.iter())
            .copied()
            .collect();
        let shifted_evals: Vec<C::ScalarField> = memory.claimed_evaluations.shifted_witness.iter()
            .copied()
            .collect();

        let unshifted_rhos = make_batching_challenges::<C, H>(
            &mut transcript, "HyperNova:rho_unshifted", num_unshifted,
        );
        let shifted_rhos = make_batching_challenges::<C, H>(
            &mut transcript, "HyperNova:rho_shifted", num_shifted,
        );

        let batched_unshifted_commit = folding_prover::batch_commitments::<C>(
            &unshifted_commits, &unshifted_rhos,
        );
        let batched_shifted_commit = folding_prover::batch_commitments::<C>(
            &shifted_commits, &shifted_rhos,
        );

        let batched_unshifted_eval = folding_prover::batch_evaluations(
            &unshifted_evals, &unshifted_rhos,
        );
        let batched_shifted_eval = folding_prover::batch_evaluations(
            &shifted_evals, &shifted_rhos,
        );

        // Use the ACTUAL multivariate_challenge from sumcheck (not gate_challenges)
        let verifier_claim = MultilinearBatchingVerifierClaim {
            challenge: multivariate_challenge,
            non_shifted_evaluation: batched_unshifted_eval,
            shifted_evaluation: batched_shifted_eval,
            non_shifted_commitment: batched_unshifted_commit,
            shifted_commitment: batched_shifted_commit,
        };

        Ok((sumcheck_verified, verifier_claim, transcript))
    }

    /// Verify a folding proof (combines old accumulator with new instance).
    ///
    /// 1. Verifies the new instance via instance_to_accumulator (actual sumcheck)
    /// 2. Verifies the batching sumcheck
    /// 3. Combines verifier claims with γ from transcript
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
        // Step 1: Verify new instance (runs actual sumcheck verification)
        let (instance_verified, instance_claim, mut transcript) =
            Self::instance_to_accumulator::<C, H, P>(
                honk_proof, public_inputs, verifying_key, has_zk,
            )?;

        // Step 2: Verify batching sumcheck
        // The prover sent BatchingSumcheck round data to the transcript.
        // The verifier reads it and checks consistency.
        let alpha = transcript.get_challenge::<C>("BatchingSumcheck:alpha".to_string());
        let log_n = accumulator.challenge.len();

        let (batching_verified, _batching_challenge) =
            super::batching_sumcheck::verify_batching_sumcheck::<C, H>(
                accumulator.non_shifted_evaluation,
                accumulator.shifted_evaluation,
                instance_claim.non_shifted_evaluation,
                instance_claim.shifted_evaluation,
                alpha,
                log_n,
                &mut transcript,
            );

        // Step 3: Combine verifier claims with γ from transcript
        let gamma = transcript.get_challenge::<C>("BatchingSumcheck:gamma".to_string());

        let combined_ns_commit: C::Affine = (
            C::from(instance_claim.non_shifted_commitment) +
            C::from(accumulator.non_shifted_commitment) * gamma
        ).into();
        let combined_s_commit: C::Affine = (
            C::from(instance_claim.shifted_commitment) +
            C::from(accumulator.shifted_commitment) * gamma
        ).into();

        let new_claim = MultilinearBatchingVerifierClaim {
            challenge: instance_claim.challenge,
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
