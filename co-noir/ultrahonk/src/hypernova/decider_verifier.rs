// HyperNova Decider Verifier
//
// Verifies the final IVC proof by checking the polynomial opening
// at the accumulated challenge point via Shplemini + KZG pairing.
//
// Algorithm:
//   1. Extract commitments and evaluations from the verifier accumulator
//   2. Run Shplemini verifier (compute batch opening claim)
//   3. Run KZG pairing check: e(P0, [1]₂) = e(P1, [x]₂)
//   4. Return verification result
//
// Reference: barretenberg/hypernova/hypernova_decider_verifier.hpp

use ark_ec::{pairing::Pairing, CurveGroup};
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::TranscriptFieldType,
    transcript::{Transcript, TranscriptHasher},
};
use noir_types::HonkProof;

use crate::{
    decider::decider_verifier::DeciderVerifier,
    multilinear_batching::MultilinearBatchingVerifierClaim,
    ultra_verifier::HonkVerifyResult,
};

/// The HyperNova decider verifier — checks the final IVC proof.
///
/// Takes the accumulated verifier claim (commitments + evaluations + challenge)
/// and verifies the Shplemini + KZG opening proof from the decider prover.
pub struct HypernovaDeciderVerifier;

impl HypernovaDeciderVerifier {
    /// Verify the final proof against an accumulated verifier claim.
    ///
    /// Runs ShpleminiVerifier + KZG pairing check.
    /// Returns true if the IVC proof is valid.
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

        // The verifier needs to:
        // 1. Setup claim batcher with accumulator's commitments + evaluations
        //    - Unshifted: (non_shifted_commitment, non_shifted_evaluation)
        //    - Shifted: (shifted_commitment, shifted_evaluation)
        // 2. Run ShpleminiVerifier::compute_batch_opening_claim(
        //        padding_indicator, claim_batcher, challenge, generator, transcript
        //    )
        // 3. Run KZG::reduce_verify_batch_opening_claim → PairingPoints (P0, P1)
        // 4. Execute pairing check: e(P0, [1]₂) = e(P1, [x]₂)

        // TODO: Connect to existing Shplemini verifier + KZG pairing check.
        //
        // The existing DeciderVerifier does this for the standard UltraHonk proof.
        // For HyperNova, the inputs are different (accumulated claim vs per-circuit
        // polynomials), but the PCS verification logic is identical.
        //
        // The key difference: instead of N individual polynomial commitments,
        // we have 2 batched commitments (non-shifted + shifted) at 1 challenge point.

        let _ = (accumulator, crs, transcript);
        todo!(
            "Connect to Shplemini verifier + KZG pairing. \
             Need to construct ShpleminiVerifierOpeningClaim from the accumulated \
             commitments/evaluations and run the existing pairing check."
        )
    }
}
