// HyperNova Folding Scheme for IVC
//
// Implements the folding protocol that enables Incremental Verifiable Computation:
//   1. Convert a circuit instance to an accumulator (via Oink + Sumcheck)
//   2. Fold a new instance into an existing accumulator (via MultilinearBatching)
//   3. Produce a final proof from the accumulated claim (Decider)
//
// Data flow:
//   ProverInstance → Oink → Sumcheck → batch → Accumulator
//   Accumulator + new Instance → fold → new Accumulator
//   final Accumulator → Decider → HonkProof
//
// Reference: barretenberg/hypernova/

pub mod folding_prover;
pub mod folding_verifier;
pub mod decider_prover;
pub mod decider_verifier;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;

/// Generate batching challenges for combining polynomials into a single accumulator.
///
/// Returns (unshifted_challenges, shifted_challenges), each starting with implicit 1.
/// The i-th polynomial is scaled by challenge[i] during batching.
pub fn get_batching_challenges<F: PrimeField>(
    num_unshifted: usize,
    num_shifted: usize,
    // In the real implementation, these come from the transcript.
    // For now, we take them as parameters.
    unshifted_rhos: &[F],
    shifted_rhos: &[F],
) -> (Vec<F>, Vec<F>) {
    // First coefficient is implicit 1
    let mut unshifted = Vec::with_capacity(num_unshifted);
    unshifted.push(F::one());
    unshifted.extend_from_slice(&unshifted_rhos[..num_unshifted - 1]);

    let mut shifted = Vec::with_capacity(num_shifted);
    shifted.push(F::one());
    shifted.extend_from_slice(&shifted_rhos[..num_shifted - 1]);

    (unshifted, shifted)
}
