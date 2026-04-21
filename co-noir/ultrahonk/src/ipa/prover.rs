// IPA Prover
//
// Computes an inner product argument proof for opening a polynomial
// at a single evaluation point.
//
// Algorithm (log(d) rounds):
//   1. Get generator challenge u, compute U = u·G (auxiliary generator)
//   2. Set a = polynomial coefficients, b = (1, β, β², ...), G = CRS
//   3. For each round i:
//      a. Compute L_i = <a_lo, G_hi> + <a_lo, b_hi>·U
//      b. Compute R_i = <a_hi, G_lo> + <a_hi, b_lo>·U
//      c. Send L_i, R_i to transcript
//      d. Get challenge u_i
//      e. Fold: G = G_lo + u_i⁻¹·G_hi
//      f. Fold: a = a_lo + u_i·a_hi
//      g. Fold: b = b_lo + u_i⁻¹·b_hi
//   4. Send final a₀ to transcript
//
// Reference: barretenberg/commitment_schemes/ipa/ipa.hpp

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, PrimeField, Zero};
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::TranscriptFieldType,
    transcript::{Transcript, TranscriptHasher},
};

use super::{IpaCommitmentKey, IpaOpeningClaim};

/// Compute an IPA opening proof.
///
/// Writes L_i, R_i commitments and final scalar a₀ to the transcript.
pub fn ipa_prove<C, H>(
    ck: &IpaCommitmentKey<C>,
    opening_claim: &IpaOpeningClaim<C>,
    transcript: &mut Transcript<TranscriptFieldType, H>,
) where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    let poly_length = opening_claim.polynomial.len();
    assert!(poly_length.is_power_of_two(), "polynomial length must be power of 2");
    let log_n = poly_length.ilog2() as usize;

    // Step 1: Add claim to hash buffer (NOT to proof bytes — verifier knows these)
    let commitment = ck.commit(&opening_claim.polynomial);
    transcript.add_point_to_hash_buffer::<C>("IPA:commitment".to_string(), commitment);
    transcript.add_fr_to_hash_buffer::<C>("IPA:challenge".to_string(), opening_claim.challenge);
    transcript.add_fr_to_hash_buffer::<C>("IPA:evaluation".to_string(), opening_claim.evaluation);

    // Step 2: Get generator challenge and compute auxiliary generator U
    let generator_challenge = transcript.get_challenge::<C>("IPA:generator_challenge".to_string());
    let aux_generator: C = <C::Affine as AffineRepr>::generator().into_group() * generator_challenge;

    // Step 3: Initialize vectors
    let mut a_vec = opening_claim.polynomial.clone();
    let mut g_vec: Vec<C::Affine> = ck.generators[..poly_length].to_vec();

    // Compute b = (1, β, β², ..., β^{d-1})
    let beta = opening_claim.challenge;
    let mut b_vec = Vec::with_capacity(poly_length);
    let mut b_power = C::ScalarField::one();
    for _ in 0..poly_length {
        b_vec.push(b_power);
        b_power *= beta;
    }

    // Step 4: IPA reduction rounds
    let mut round_size = poly_length;

    for i in 0..log_n {
        round_size /= 2;

        // Compute inner products for cross-terms
        let mut inner_prod_l = C::ScalarField::zero();
        let mut inner_prod_r = C::ScalarField::zero();
        for j in 0..round_size {
            inner_prod_l += a_vec[j] * b_vec[round_size + j];       // <a_lo, b_hi>
            inner_prod_r += a_vec[round_size + j] * b_vec[j];       // <a_hi, b_lo>
        }

        // L_i = <a_lo, G_hi> + <a_lo, b_hi>·U
        let l_msm = C::msm_unchecked(
            &g_vec[round_size..2 * round_size],
            &a_vec[..round_size],
        );
        let l_i: C::Affine = (l_msm + aux_generator * inner_prod_l).into();

        // R_i = <a_hi, G_lo> + <a_hi, b_lo>·U
        let r_msm = C::msm_unchecked(
            &g_vec[..round_size],
            &a_vec[round_size..2 * round_size],
        );
        let r_i: C::Affine = (r_msm + aux_generator * inner_prod_r).into();

        // Send L_i, R_i to transcript
        let index = log_n - i - 1;
        transcript.send_point_to_verifier::<C>(format!("IPA:L_{index}"), l_i);
        transcript.send_point_to_verifier::<C>(format!("IPA:R_{index}"), r_i);

        // Get round challenge
        let round_challenge = transcript.get_challenge::<C>(
            format!("IPA:round_challenge_{index}"),
        );
        let round_challenge_inv = round_challenge.inverse().expect("challenge must be nonzero");

        // Fold vectors (compute new values, then write)
        let new_g: Vec<C::Affine> = (0..round_size)
            .map(|j| (C::from(g_vec[j]) + C::from(g_vec[round_size + j]) * round_challenge_inv).into())
            .collect();
        let new_a: Vec<C::ScalarField> = (0..round_size)
            .map(|j| a_vec[j] + round_challenge * a_vec[round_size + j])
            .collect();
        let new_b: Vec<C::ScalarField> = (0..round_size)
            .map(|j| b_vec[j] + round_challenge_inv * b_vec[round_size + j])
            .collect();
        g_vec[..round_size].copy_from_slice(&new_g);
        a_vec[..round_size].copy_from_slice(&new_a);
        b_vec[..round_size].copy_from_slice(&new_b);
    }

    // Step 5: Send final values
    transcript.send_point_to_verifier::<C>("IPA:G_0".to_string(), g_vec[0]);
    transcript.send_fr_to_verifier::<C>("IPA:a_0".to_string(), a_vec[0]);
}
