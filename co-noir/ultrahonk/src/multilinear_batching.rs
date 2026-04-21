// Multilinear Batching — Accumulator data structures for IVC/HyperNova
//
// In HyperNova folding, we reduce two polynomial evaluation claims to one via
// sumcheck. The prover holds polynomials; the verifier holds only commitments.
//
// Each claim asserts: "polynomial P evaluated at point r equals v", i.e., P(r) = v.
//   - Accumulator claim: P_acc(r_acc) = v_acc  (from previous folding rounds)
//   - Instance claim:    P_inst(r_inst) = v_inst (from the incoming circuit)
//
// The multilinear batching sumcheck proves both claims simultaneously. After
// sumcheck, both claims are reduced to evaluations at a new random point u,
// producing a single combined claim verifiable with one polynomial opening.
//
// Reference: barretenberg/multilinear_batching/

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_noir_common::polynomials::polynomial::Polynomial;

/// Prover's claim for multilinear batching.
///
/// Contains the full polynomials (needed for sumcheck evaluation) plus
/// commitments and evaluation claims. Used as:
/// - Input to the multilinear batching prover (two claims → one)
/// - Output from HyperNova folding prover
/// - Accumulator state across IVC rounds
#[derive(Clone, Debug)]
pub struct MultilinearBatchingProverClaim<P: CurveGroup> {
    /// Evaluation point r (length = log(circuit_size))
    pub challenge: Vec<P::ScalarField>,
    /// Claimed value: P(r) for the non-shifted polynomial
    pub non_shifted_evaluation: P::ScalarField,
    /// Claimed value: P_shifted(r) for the shifted polynomial
    pub shifted_evaluation: P::ScalarField,
    /// The non-shifted polynomial P
    pub non_shifted_polynomial: Polynomial<P::ScalarField>,
    /// The shiftable polynomial (pre-shift form)
    pub shifted_polynomial: Polynomial<P::ScalarField>,
    /// Commitment [P] (non-shifted)
    pub non_shifted_commitment: P::Affine,
    /// Commitment [P_shifted]
    pub shifted_commitment: P::Affine,
    /// Size of the polynomial domain (power of 2)
    pub dyadic_size: usize,
}

/// Verifier's claim for multilinear batching.
///
/// Contains only commitments and evaluation claims (no polynomials).
/// Used by the verifier to check the batching proof.
#[derive(Clone, Debug)]
pub struct MultilinearBatchingVerifierClaim<P: CurveGroup> {
    /// Evaluation point r
    pub challenge: Vec<P::ScalarField>,
    /// Claimed value P(r)
    pub non_shifted_evaluation: P::ScalarField,
    /// Claimed value P_shifted(r)
    pub shifted_evaluation: P::ScalarField,
    /// Commitment [P]
    pub non_shifted_commitment: P::Affine,
    /// Commitment [P_shifted]
    pub shifted_commitment: P::Affine,
}

impl<P: CurveGroup> MultilinearBatchingVerifierClaim<P> {
    /// Extract verifier claim from prover claim (drop polynomials).
    pub fn from_prover_claim(prover: &MultilinearBatchingProverClaim<P>) -> Self {
        Self {
            challenge: prover.challenge.clone(),
            non_shifted_evaluation: prover.non_shifted_evaluation,
            shifted_evaluation: prover.shifted_evaluation,
            non_shifted_commitment: prover.non_shifted_commitment,
            shifted_commitment: prover.shifted_commitment,
        }
    }
}

impl<P: CurveGroup> Default for MultilinearBatchingProverClaim<P> {
    fn default() -> Self {
        Self {
            challenge: Vec::new(),
            non_shifted_evaluation: P::ScalarField::default(),
            shifted_evaluation: P::ScalarField::default(),
            non_shifted_polynomial: Polynomial::default(),
            shifted_polynomial: Polynomial::default(),
            non_shifted_commitment: P::Affine::default(),
            shifted_commitment: P::Affine::default(),
            dyadic_size: 0,
        }
    }
}

impl<P: CurveGroup> Default for MultilinearBatchingVerifierClaim<P> {
    fn default() -> Self {
        Self {
            challenge: Vec::new(),
            non_shifted_evaluation: P::ScalarField::default(),
            shifted_evaluation: P::ScalarField::default(),
            non_shifted_commitment: P::Affine::default(),
            shifted_commitment: P::Affine::default(),
        }
    }
}
