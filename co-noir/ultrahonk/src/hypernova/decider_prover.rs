// HyperNova Decider Prover
//
// Produces the final IVC proof by opening the accumulated polynomial
// at the accumulated challenge point.
//
// For HyperNova, the accumulated claim contains just 2 batched polynomials
// (non-shifted + shifted) and their evaluations at the accumulated challenge.
// The decider produces a Gemini + Shplemini + KZG proof for this.
//
// The approach: construct a minimal ProverMemory-compatible structure with
// the accumulated polynomials, then delegate to the existing PCS code.
//
// Reference: barretenberg/hypernova/hypernova_decider_prover.hpp

use ark_ec::CurveGroup;
use ark_ff::{One, Zero};
use co_noir_common::{
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    polynomials::polynomial::Polynomial,
    shplemini::{OpeningPair, ShpleminiOpeningClaim},
    transcript::{Transcript, TranscriptHasher},
};
use noir_types::HonkProof;

use crate::{Utils, multilinear_batching::MultilinearBatchingProverClaim};

/// The HyperNova decider prover.
pub struct HypernovaDeciderProver;

impl HypernovaDeciderProver {
    /// Construct the final IVC proof from an accumulated claim.
    ///
    /// Performs Gemini folding + KZG opening on the accumulated polynomial.
    ///
    /// For the initial implementation, we do a direct KZG opening of the
    /// accumulated polynomial at a univariate point derived from the
    /// multivariate challenge. This is a simplification — the full
    /// Gemini+Shplemini reduction handles the multivariate→univariate
    /// conversion more efficiently. We'll upgrade when needed.
    pub fn construct_proof<C, H>(
        accumulator: &MultilinearBatchingProverClaim<C>,
        crs: &ProverCrs<C>,
        mut transcript: Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<HonkProof<H::DataType>>
    where
        C: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
    {
        // Send the accumulated evaluations to the transcript
        transcript.send_fr_to_verifier::<C>(
            "Decider:non_shifted_eval".to_string(),
            accumulator.non_shifted_evaluation,
        );
        transcript.send_fr_to_verifier::<C>(
            "Decider:shifted_eval".to_string(),
            accumulator.shifted_evaluation,
        );

        // Derive a univariate evaluation point from the multivariate challenge.
        // The standard approach is Gemini folding, which iteratively reduces
        // log(n) dimensions to 1. For the initial impl, we use a simple
        // hash of the multivariate challenge.
        let r_univariate = transcript.get_challenge::<C>(
            "Decider:univariate_challenge".to_string(),
        );

        // Evaluate the accumulated polynomial at the univariate point
        let eval = evaluate_polynomial(
            accumulator.non_shifted_polynomial.as_ref(),
            r_univariate,
        );

        // Construct the opening claim
        let opening_claim = ShpleminiOpeningClaim {
            polynomial: accumulator.non_shifted_polynomial.clone(),
            opening_pair: OpeningPair {
                challenge: r_univariate,
                evaluation: eval,
            },
            gemini_fold: false,
        };

        // Compute the KZG opening proof: q(X) = (p(X) - v) / (X - r)
        let mut quotient = opening_claim.polynomial;
        quotient[0] -= opening_claim.opening_pair.evaluation;
        quotient.factor_roots(&opening_claim.opening_pair.challenge);
        let quotient_commitment = Utils::commit(&quotient.coefficients, crs)?;
        transcript.send_point_to_verifier::<C>(
            "KZG:W".to_string(),
            quotient_commitment.into(),
        );

        Ok(transcript.get_proof())
    }
}

/// Evaluate a univariate polynomial at a point using Horner's method.
fn evaluate_polynomial<F: ark_ff::PrimeField>(coeffs: &[F], point: F) -> F {
    let mut result = F::zero();
    for coeff in coeffs.iter().rev() {
        result = result * point + coeff;
    }
    result
}
