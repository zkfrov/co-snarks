pub(crate) mod shplemini_prover;
pub(crate) mod shplemini_verifier;
pub(crate) mod types;

/// Type alias for accessing Gemini/Shplemini static helper functions.
/// These are implemented as methods on `Decider<P, H>` but are logically
/// static (they don't use `self` except for `compute_batched_polys`).
/// HyperNova's decider calls them directly with pre-batched polynomials.
pub(crate) type ShpleminiProverHelper<P, H> = super::decider_prover::Decider<P, H>;
