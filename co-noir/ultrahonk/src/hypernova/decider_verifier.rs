// HyperNova Decider Verifier
//
// Verifies the final IVC proof by checking the KZG polynomial opening
// at the accumulated challenge point.
//
// Reference: barretenberg/hypernova/hypernova_decider_verifier.hpp

use ark_ec::{AffineRepr, pairing::Pairing, CurveGroup};
use ark_ff::{One, Zero};
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::TranscriptFieldType,
    transcript::{Transcript, TranscriptHasher},
};
use noir_types::HonkProof;

use crate::{
    Utils,
    decider::decider_verifier::DeciderVerifier,
    multilinear_batching::MultilinearBatchingVerifierClaim,
    ultra_verifier::HonkVerifyResult,
};

/// The HyperNova decider verifier.
pub struct HypernovaDeciderVerifier;

impl HypernovaDeciderVerifier {
    /// Verify the final IVC proof against an accumulated verifier claim.
    ///
    /// Reads the KZG opening proof from the transcript and performs the
    /// pairing check: e(P0, [1]₂) = e(P1, [x]₂)
    pub fn verify<C, H, P>(
        accumulator: &MultilinearBatchingVerifierClaim<C>,
        proof: HonkProof<H::DataType>,
        crs: &P::G2Affine,
    ) -> HonkVerifyResult<bool>
    where
        C: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
        P: Pairing<G1 = C, G1Affine = C::Affine>,
    {
        let mut transcript = Transcript::<TranscriptFieldType, H>::new_verifier(proof);

        // Read the evaluations from the transcript (sent by prover)
        let non_shifted_eval = transcript.receive_fr_from_prover::<C>(
            "Decider:non_shifted_eval".to_string(),
        )?;
        let shifted_eval = transcript.receive_fr_from_prover::<C>(
            "Decider:shifted_eval".to_string(),
        )?;

        // Check evaluations match the accumulator
        if non_shifted_eval != accumulator.non_shifted_evaluation {
            return Ok(false);
        }
        if shifted_eval != accumulator.shifted_evaluation {
            return Ok(false);
        }

        // Derive the same univariate evaluation point
        let r_univariate = transcript.get_challenge::<C>(
            "Decider:univariate_challenge".to_string(),
        );

        // Read the KZG quotient commitment W from the transcript
        let w_commitment = transcript.receive_point_from_prover::<C>(
            "KZG:W".to_string(),
        )?;

        // KZG verification: check that [p] - v·[1] = [W]·(x - r)
        //
        // Pairing check: e([p] - v·[1] + r·[W], [1]₂) = e([W], [x]₂)
        //
        // P0 = [p] - v·G + r·[W]
        // P1 = -[W]
        let generator = C::Affine::generator();
        let commitment: C = accumulator.non_shifted_commitment.into();
        let w: C = w_commitment.into();

        let p0: C = commitment
            - generator.into_group() * non_shifted_eval
            + w * r_univariate;
        let p1: C = -w;

        // Execute pairing check
        let g2_gen = <P::G2 as CurveGroup>::Affine::generator();
        let result = DeciderVerifier::<C, H>::pairing_check::<P>(
            p0.into(),
            p1.into(),
            *crs,
            g2_gen,
        );

        Ok(result)
    }
}
