// IPA (Inner Product Argument) Commitment Scheme
//
// Used by ECCVM for polynomial commitment over the Grumpkin curve.
// KZG requires pairings (only works on BN254); IPA works on any curve.
//
// The protocol proves: <a, G> = C and <a, b> = v
// where:
//   a = polynomial coefficients
//   b = powers of the evaluation point (1, β, β², ...)
//   G = CRS generators (G₀, G₁, ..., G_{d-1})
//   C = commitment = <a, G>
//   v = evaluation = f(β)
//
// The prover runs log(d) rounds, halving vectors each time.
// Each round sends L_i, R_i (cross-term commitments).
// After k rounds, sends final scalar a₀.
//
// Reference: barretenberg/commitment_schemes/ipa/ipa.hpp

pub mod prover;
pub mod verifier;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;

/// IPA opening claim: polynomial + evaluation point + evaluation value.
#[derive(Clone)]
pub struct IpaOpeningClaim<P: CurveGroup> {
    /// Polynomial coefficients
    pub polynomial: Vec<P::ScalarField>,
    /// Evaluation point β
    pub challenge: P::ScalarField,
    /// Claimed evaluation f(β)
    pub evaluation: P::ScalarField,
}

/// IPA commitment key: the CRS generators G₀, ..., G_{d-1}.
pub struct IpaCommitmentKey<P: CurveGroup> {
    /// Generator points (SRS)
    pub generators: Vec<P::Affine>,
}

impl<P: CurveGroup> IpaCommitmentKey<P> {
    /// Create a commitment key with `n` generators.
    ///
    /// In production, these come from a trusted setup ceremony.
    /// For testing, we derive them deterministically.
    pub fn new(n: usize) -> Self {
        use ark_ec::hashing::{HashToCurve, curve_maps::wb::WBMap};
        use ark_ff::Zero;

        // Simple deterministic generator derivation for testing.
        // Production would use a proper SRS.
        let mut generators = Vec::with_capacity(n);
        let g = P::generator();
        let mut acc = g;
        for _ in 0..n {
            generators.push(acc.into());
            acc += g; // Simple sequential points (NOT secure for production)
        }

        Self { generators }
    }

    /// Commit to a polynomial: C = <coeffs, generators> = Σ coeffs[i] · G[i]
    pub fn commit(&self, coeffs: &[P::ScalarField]) -> P::Affine {
        use ark_ec::VariableBaseMSM;
        let n = coeffs.len().min(self.generators.len());
        P::msm_unchecked(&self.generators[..n], &coeffs[..n]).into()
    }
}

/// IPA verification key: same generators as commitment key.
pub type IpaVerificationKey<P> = IpaCommitmentKey<P>;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective as Bn254G1};
    use ark_ff::{One, UniformRand, Zero};
    use co_noir_common::honk_proof::TranscriptFieldType;
    use co_noir_common::transcript::{Poseidon2Sponge, Transcript};

    type TestCurve = Bn254G1;
    type TestHasher = Poseidon2Sponge;

    fn eval_poly(coeffs: &[Fr], point: Fr) -> Fr {
        let mut result = Fr::zero();
        for c in coeffs.iter().rev() {
            result = result * point + c;
        }
        result
    }

    #[test]
    fn ipa_prove_verify_roundtrip() {
        let log_n = 4;
        let n = 1 << log_n;
        let mut rng = rand::thread_rng();

        let polynomial: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let challenge = Fr::rand(&mut rng);
        let evaluation = eval_poly(&polynomial, challenge);

        let ck = IpaCommitmentKey::<TestCurve>::new(n);

        let claim = IpaOpeningClaim {
            polynomial: polynomial.clone(),
            challenge,
            evaluation,
        };
        let mut prover_transcript = Transcript::<TranscriptFieldType, TestHasher>::new();
        prover::ipa_prove::<TestCurve, TestHasher>(&ck, &claim, &mut prover_transcript);
        let proof = prover_transcript.get_proof();

        let commitment = ck.commit(&polynomial);
        let mut verifier_transcript =
            Transcript::<TranscriptFieldType, TestHasher>::new_verifier(proof);
        let verified = verifier::ipa_verify::<TestCurve, TestHasher>(
            &ck, commitment, challenge, evaluation, &mut verifier_transcript,
        );

        assert!(verified, "IPA proof should verify");
    }

    #[test]
    fn ipa_wrong_evaluation_fails() {
        let log_n = 3;
        let n = 1 << log_n;
        let mut rng = rand::thread_rng();

        let polynomial: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let challenge = Fr::rand(&mut rng);
        let correct_eval = eval_poly(&polynomial, challenge);
        let wrong_eval = correct_eval + Fr::one();

        let ck = IpaCommitmentKey::<TestCurve>::new(n);

        let claim = IpaOpeningClaim {
            polynomial: polynomial.clone(),
            challenge,
            evaluation: wrong_eval,
        };
        let mut prover_transcript = Transcript::<TranscriptFieldType, TestHasher>::new();
        prover::ipa_prove::<TestCurve, TestHasher>(&ck, &claim, &mut prover_transcript);
        let proof = prover_transcript.get_proof();

        let commitment = ck.commit(&polynomial);
        let mut verifier_transcript =
            Transcript::<TranscriptFieldType, TestHasher>::new_verifier(proof);
        let verified = verifier::ipa_verify::<TestCurve, TestHasher>(
            &ck, commitment, challenge, wrong_eval, &mut verifier_transcript,
        );

        assert!(!verified, "IPA proof with wrong evaluation should NOT verify");
    }
}

