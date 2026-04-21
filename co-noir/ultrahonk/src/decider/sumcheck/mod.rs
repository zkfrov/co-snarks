pub(crate) mod sumcheck_prover;
pub(crate) mod sumcheck_round_prover;
pub(crate) mod sumcheck_round_verifier;
pub(crate) mod sumcheck_verifier;
pub(crate) mod zk_data;

use ark_ff::PrimeField;

pub(crate) struct SumcheckOutput<F: PrimeField> {
    pub(crate) challenges: Vec<F>,
    pub(crate) claimed_libra_evaluation: Option<F>,
    /// For HyperNova: claimed evaluations of all polynomials at the challenge point.
    /// None in the standard UltraHonk flow (evaluations go directly to transcript).
    /// Some when running sumcheck for folding (needed for batching into accumulator).
    pub(crate) claimed_evaluations: Option<super::types::ClaimedEvaluations<F>>,
}

pub struct SumcheckVerifierOutput<F: PrimeField> {
    pub multivariate_challenge: Vec<F>,
    pub verified: bool,
    pub claimed_libra_evaluation: Option<F>,
}
