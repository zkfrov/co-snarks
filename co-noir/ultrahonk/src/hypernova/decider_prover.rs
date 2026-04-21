// HyperNova Decider Prover
//
// Produces the final IVC proof by opening the accumulated polynomial
// at the accumulated challenge point using Shplemini + KZG.
//
// This is the last step of IVC: after all circuit instances have been
// folded into a single accumulator, the decider proves that the
// batched polynomial commitment can be opened correctly.
//
// Algorithm:
//   1. Extract polynomials from the accumulator
//   2. Run Shplemini (multivariate → univariate polynomial opening)
//   3. Run KZG opening proof
//   4. Return proof bytes
//
// Reference: barretenberg/hypernova/hypernova_decider_prover.hpp

use ark_ec::CurveGroup;
use co_noir_common::{
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    transcript::{Transcript, TranscriptHasher},
};
use noir_types::HonkProof;

use crate::multilinear_batching::MultilinearBatchingProverClaim;

/// The HyperNova decider prover — produces the final IVC proof.
///
/// Takes the accumulated claim (batched polynomial + challenge point)
/// and produces a Shplemini + KZG opening proof.
pub struct HypernovaDeciderProver;

impl HypernovaDeciderProver {
    /// Construct the final proof from an accumulated claim.
    ///
    /// This is equivalent to the PCS rounds of the standard UltraHonk
    /// Decider, but operating on the accumulated (batched) polynomial
    /// rather than the individual circuit polynomials.
    ///
    /// The existing Decider::execute_pcs_rounds does exactly this:
    ///   - Shplemini: reduce multivariate opening to univariate
    ///   - KZG: produce the univariate opening proof
    ///
    /// For HyperNova, we call the same Shplemini + KZG code but with
    /// the accumulated polynomial and challenge point.
    pub fn construct_proof<C, H>(
        accumulator: &MultilinearBatchingProverClaim<C>,
        crs: &ProverCrs<C>,
        mut transcript: Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<HonkProof<H::DataType>>
    where
        C: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
    {
        // The accumulated polynomial and challenge point
        let _polynomial = &accumulator.non_shifted_polynomial;
        let _shifted_polynomial = &accumulator.shifted_polynomial;
        let _challenge = &accumulator.challenge;

        // TODO: Connect to existing Shplemini + KZG infrastructure.
        //
        // The flow is:
        // 1. Setup polynomial batcher (GeminiProver):
        //    - set_unshifted(non_shifted_polynomial)
        //    - set_to_be_shifted_by_one(shifted_polynomial)
        // 2. Run ShpleminiProver::prove(
        //        actual_size, polynomial_batcher, challenge, crs, transcript
        //    ) → ShpleminiOpeningClaim
        // 3. Run KZG opening:
        //    - quotient = (polynomial - evaluation) / (X - challenge)
        //    - commit(quotient) → send to transcript
        //
        // The existing Decider::execute_pcs_rounds + compute_opening_proof
        // handles this. We need to extract and reuse that code.

        let _ = crs;
        todo!(
            "Connect to Shplemini + KZG. The accumulated polynomial is ready; \
             need to call the existing PCS infrastructure with the accumulated \
             challenge point and polynomial."
        )
    }
}
