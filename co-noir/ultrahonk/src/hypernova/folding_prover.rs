// HyperNova Folding Prover
//
// Converts circuit instances to accumulators and folds them together.
//
// Algorithm:
//   instance_to_accumulator(instance):
//     1. Run OinkProver (wire commitments, grand products)
//     2. Run SumcheckProver (evaluate all relations at random point r)
//     3. Batch polynomials, commitments, and evaluations with ρ challenges
//     → Accumulator with single batched polynomial claim at point r
//
//   fold(old_accumulator, new_instance):
//     1. Convert new instance to accumulator (step above)
//     2. Run MultilinearBatchingProver (sumcheck to reduce two claims to one)
//     → New accumulator with combined claim at new random point u
//
// Reference: barretenberg/hypernova/hypernova_prover.hpp

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_noir_common::polynomials::polynomial::Polynomial;
use crate::multilinear_batching::MultilinearBatchingProverClaim;

/// The HyperNova folding prover.
///
/// Orchestrates Oink + Sumcheck + polynomial batching to produce and
/// fold accumulators for IVC.
pub struct HypernovaFoldingProver<P: CurveGroup> {
    _marker: std::marker::PhantomData<P>,
}

impl<P: CurveGroup> HypernovaFoldingProver<P> {
    /// Convert a circuit instance to an initial accumulator.
    ///
    /// Runs Oink (wire commitments) + Sumcheck (relation evaluation at random r),
    /// then batches all polynomials/commitments into a single claim.
    ///
    /// This is the entry point for the first IVC step.
    pub fn instance_to_accumulator(
        // TODO: takes ProverInstance, VerificationKey, transcript
        // Returns MultilinearBatchingProverClaim
    ) -> MultilinearBatchingProverClaim<P> {
        // Phase 2 implementation:
        // 1. OinkProver::prove(instance) → committed polynomials
        // 2. SumcheckProver::prove(polynomials, alpha, gate_challenges)
        //    → SumcheckOutput { challenge: r, claimed_evaluations }
        // 3. sumcheck_output_to_accumulator(output, instance, vk)
        //    → batch polynomials with ρ challenges
        //    → batch commitments with same ρ
        //    → batch evaluations with same ρ
        //    → Accumulator { challenge: r, batched_poly, batched_commit, batched_eval }
        todo!("Phase 2: implement instance_to_accumulator")
    }

    /// Fold a new instance into an existing accumulator.
    ///
    /// 1. Converts the new instance to an accumulator
    /// 2. Runs MultilinearBatching sumcheck to reduce both claims to one
    ///
    /// Returns (proof_bytes, new_accumulator).
    pub fn fold(
        _accumulator: MultilinearBatchingProverClaim<P>,
        // TODO: new_instance, vk, transcript
    ) -> (Vec<u8>, MultilinearBatchingProverClaim<P>) {
        // Phase 2 implementation:
        // 1. incoming = instance_to_accumulator(new_instance)
        // 2. MultilinearBatchingProver::new(accumulator, incoming, transcript)
        // 3. proof = batching_prover.construct_proof()
        //    - Sends accumulator commitments
        //    - Sends accumulator challenge + evaluations
        //    - Runs sumcheck on: P_acc(x)·eq(x,r_acc) + P_inst(x)·eq(x,r_inst) = v
        // 4. new_accumulator = batching_prover.compute_new_claim()
        //    - P_new = P_inst + γ·P_acc
        //    - v_new = v_inst(u) + γ·v_acc(u)
        // 5. Return (proof, new_accumulator)
        todo!("Phase 2: implement fold")
    }

    /// Batch sumcheck output polynomials into a single accumulator claim.
    ///
    /// Given individual polynomial evaluations from sumcheck, combines them
    /// using batching challenges ρ:
    ///   P_batched = Σ ρᵢ·Pᵢ,  v_batched = Σ ρᵢ·vᵢ,  [P_batched] = Σ ρᵢ·[Pᵢ]
    fn sumcheck_output_to_accumulator(
        // TODO: sumcheck_output, instance, vk, batching_challenges
    ) -> MultilinearBatchingProverClaim<P> {
        // 1. Get batching challenges from transcript
        // 2. Batch unshifted polynomials: P = Σ ρᵢ·pᵢ
        // 3. Batch shifted polynomials: P̃ = Σ ρᵢ·p̃ᵢ
        // 4. Batch evaluations: v = Σ ρᵢ·vᵢ
        // 5. Batch commitments: [P] = Σ ρᵢ·[pᵢ]
        todo!("Phase 2: implement sumcheck_output_to_accumulator")
    }
}
