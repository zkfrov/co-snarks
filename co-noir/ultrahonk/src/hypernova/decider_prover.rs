// HyperNova Decider Prover
//
// Produces the final IVC proof using the full Gemini + Shplemini + KZG pipeline,
// matching barretenberg's implementation exactly.
//
// The accumulated claim contains pre-batched polynomials (non-shifted + shifted).
// The decider:
//   1. Constructs A₀(X) = batched_unshifted + batched_shifted.shifted()
//   2. Runs Gemini folding: A₀ → A₁ → ... → Aₙ₋₁ (halving at each step)
//   3. Commits fold polynomials and sends to transcript
//   4. Gets Gemini challenge r, constructs A₀₊(r) and A₀₋(-r) claims
//   5. Runs Shplonk to batch all claims into one
//   6. Runs KZG opening proof
//
// This exactly mirrors bb's HypernovaDeciderProver::construct_proof.
//
// Reference: barretenberg/hypernova/hypernova_decider_prover.cpp

use ark_ff::One;
use co_noir_common::{
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    polynomials::polynomial::Polynomial,
    shplemini::{OpeningPair, ShpleminiOpeningClaim},
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
};
use noir_types::HonkProof;

use crate::{
    Utils,
    decider::shplemini::ShpleminiProverHelper,
    multilinear_batching::MultilinearBatchingProverClaim,
};

/// The HyperNova decider prover.
pub struct HypernovaDeciderProver;

impl HypernovaDeciderProver {
    /// Construct the final IVC proof from an accumulated claim.
    ///
    /// Uses the full Gemini + Shplemini + KZG pipeline, exactly matching
    /// barretenberg's HypernovaDeciderProver.
    pub fn construct_proof<C, H>(
        accumulator: &MultilinearBatchingProverClaim<C>,
        crs: &ProverCrs<C>,
        mut transcript: Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<HonkProof<H::DataType>>
    where
        C: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
    {
        let log_n = accumulator.challenge.len();
        let virtual_log_n = log_n; // For HyperNova, no padding beyond actual log_n

        // The accumulated polynomials are already batched (F and G).
        // Construct A₀(X) = F(X) + G↺(X) = F(X) + G(X)/X
        let batched_unshifted = accumulator.non_shifted_polynomial.clone();
        let batched_to_be_shifted = accumulator.shifted_polynomial.clone();

        let mut a_0 = batched_unshifted.to_owned();
        a_0 += batched_to_be_shifted.shifted().as_ref();

        // Gemini folding: compute d-1 fold polynomials
        let fold_polynomials = ShpleminiProverHelper::<C, H>::compute_fold_polynomials(
            log_n,
            &accumulator.challenge,
            a_0,
            ZeroKnowledge::No, // HyperNova decider doesn't use ZK masking
        );

        // Commit fold polynomials and send to transcript
        for (l, f_poly) in fold_polynomials.iter().take(virtual_log_n - 1).enumerate() {
            let res = Utils::commit(&f_poly.coefficients, crs)?;
            transcript.send_point_to_verifier::<C>(
                format!("Gemini:FOLD_{}", l + 1),
                res.into(),
            );
        }

        // Get Gemini challenge r
        let r_challenge = transcript.get_challenge::<C>("Gemini:r".to_string());

        // Construct A₀₊ and A₀₋ from F and G
        let (a_0_pos, a_0_neg) =
            ShpleminiProverHelper::<C, H>::compute_partially_evaluated_batch_polynomials(
                batched_unshifted,
                batched_to_be_shifted,
                r_challenge,
            );

        // Build univariate opening claims
        let claims = ShpleminiProverHelper::<C, H>::construct_univariate_opening_claims(
            virtual_log_n,
            a_0_pos,
            a_0_neg,
            fold_polynomials,
            r_challenge,
        );

        // Send fold evaluations to verifier
        for (l, claim) in claims.iter().skip(1).take(virtual_log_n).enumerate() {
            transcript.send_fr_to_verifier::<C>(
                format!("Gemini:a_{}", l + 1),
                claim.opening_pair.evaluation,
            );
        }

        // Shplonk: batch all opening claims into one
        let nu = transcript.get_challenge::<C>("Shplonk:nu".to_string());
        let gemini_fold_pos_evaluations =
            ShpleminiProverHelper::<C, H>::compute_gemini_fold_pos_evaluations(&claims);
        let batched_quotient = ShpleminiProverHelper::<C, H>::compute_batched_quotient(
            virtual_log_n,
            &claims,
            nu,
            &gemini_fold_pos_evaluations,
            &None,
        );
        let batched_quotient_commitment =
            Utils::commit(&batched_quotient.coefficients, crs)?;
        transcript.send_point_to_verifier::<C>(
            "Shplonk:Q".to_string(),
            batched_quotient_commitment.into(),
        );

        let z = transcript.get_challenge::<C>("Shplonk:z".to_string());
        let final_claim =
            ShpleminiProverHelper::<C, H>::compute_partially_evaluated_batched_quotient(
                virtual_log_n,
                claims,
                batched_quotient,
                nu,
                z,
                &gemini_fold_pos_evaluations,
                None,
            );

        // KZG opening proof: q(X) = (p(X) - v) / (X - r)
        let mut quotient = final_claim.polynomial;
        let pair = final_claim.opening_pair;
        quotient[0] -= pair.evaluation;
        quotient.factor_roots(&pair.challenge);
        let quotient_commitment = Utils::commit(&quotient.coefficients, crs)?;
        transcript.send_point_to_verifier::<C>("KZG:W".to_string(), quotient_commitment.into());

        Ok(transcript.get_proof())
    }
}
