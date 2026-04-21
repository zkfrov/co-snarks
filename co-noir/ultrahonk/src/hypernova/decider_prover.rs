// HyperNova Decider Prover
//
// Produces the final proof from an accumulated claim. This is the last
// step of IVC: open the batched polynomial at the accumulated challenge point
// using Shplemini + KZG.
//
// Reference: barretenberg/hypernova/hypernova_decider_prover.hpp

use ark_ec::CurveGroup;
use crate::multilinear_batching::MultilinearBatchingProverClaim;

/// The HyperNova decider prover — produces the final IVC proof.
pub struct HypernovaDeciderProver<P: CurveGroup> {
    _marker: std::marker::PhantomData<P>,
}

impl<P: CurveGroup> HypernovaDeciderProver<P> {
    /// Construct the final proof from an accumulated claim.
    ///
    /// Runs Shplemini (multivariate → univariate opening) + KZG (opening proof).
    pub fn construct_proof(
        _accumulator: &MultilinearBatchingProverClaim<P>,
        // TODO: commitment_key, transcript
    ) -> Vec<u8> {
        // 1. Setup polynomial batcher with accumulator's polynomials
        //    - set_unshifted(accumulator.non_shifted_polynomial)
        //    - set_to_be_shifted(accumulator.shifted_polynomial)
        // 2. Run ShpleminiProver::prove(size, batcher, challenge, ck, transcript)
        // 3. Run KZG::compute_opening_proof(ck, opening_claim, transcript)
        // 4. Return proof bytes
        todo!("Phase 2: implement decider proof construction")
    }
}
