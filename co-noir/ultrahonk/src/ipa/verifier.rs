// IPA Verifier
//
// Verifies an inner product argument proof.
//
// The verifier:
//   1. Reconstructs the auxiliary generator U = u·G
//   2. Reads L_i, R_i from transcript for each round
//   3. Gets round challenges u_i (same as prover via Fiat-Shamir)
//   4. Computes the final commitment check:
//      C' = C + v·U + Σ (u_i·L_i + u_i⁻¹·R_i)
//      Check: C' == a₀·G_s + a₀·b₀·U
//      where G_s and b₀ are the folded generator and evaluation vector
//
// Reference: barretenberg/commitment_schemes/ipa/ipa.hpp

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, PrimeField, Zero};
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::TranscriptFieldType,
    transcript::{Transcript, TranscriptHasher},
};

use super::IpaVerificationKey;

/// Construct the s-vector from round challenges.
/// s = (1, u₀⁻¹, u₁⁻¹, u₀⁻¹u₁⁻¹, ..., Πu_i⁻¹)
///
/// s[j] = Π_{i where bit i of j is 1} u_i⁻¹
fn construct_s_vector<F: PrimeField>(u_challenges: &[F]) -> Vec<F> {
    let k = u_challenges.len();
    let n = 1 << k;
    let mut s = vec![F::one(); n];

    let u_inv: Vec<F> = u_challenges.iter()
        .map(|u| u.inverse().expect("challenge nonzero"))
        .collect();

    for i in 0..k {
        let stride = 1 << (k - 1 - i);
        for j in 0..n {
            if j & stride != 0 {
                s[j] *= u_inv[i];
            }
        }
    }
    s
}

/// Verify an IPA opening proof.
///
/// Returns true if the proof is valid.
pub fn ipa_verify<C, H>(
    vk: &IpaVerificationKey<C>,
    commitment: C::Affine,
    challenge: C::ScalarField,
    evaluation: C::ScalarField,
    transcript: &mut Transcript<TranscriptFieldType, H>,
) -> bool
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    let poly_length = vk.generators.len();
    assert!(poly_length.is_power_of_two());
    let log_n = poly_length.ilog2() as usize;

    // Add claim to hash buffer (same as prover — these are NOT in the proof bytes,
    // they just affect Fiat-Shamir. The verifier already knows commitment/challenge/evaluation.)
    transcript.add_point_to_hash_buffer::<C>("IPA:commitment".to_string(), commitment);
    transcript.add_fr_to_hash_buffer::<C>("IPA:challenge".to_string(), challenge);
    transcript.add_fr_to_hash_buffer::<C>("IPA:evaluation".to_string(), evaluation);

    // Get generator challenge and compute U
    let generator_challenge = transcript.get_challenge::<C>("IPA:generator_challenge".to_string());
    let aux_generator: C = <C::Affine as AffineRepr>::generator().into_group() * generator_challenge;

    // Read L_i, R_i and collect challenges
    let mut u_challenges = Vec::with_capacity(log_n);
    let mut l_commitments = Vec::with_capacity(log_n);
    let mut r_commitments = Vec::with_capacity(log_n);

    for i in 0..log_n {
        let index = log_n - i - 1;
        let l_i = transcript.receive_point_from_prover::<C>(format!("IPA:L_{index}"))
            .expect("L commitment");
        let r_i = transcript.receive_point_from_prover::<C>(format!("IPA:R_{index}"))
            .expect("R commitment");

        l_commitments.push(l_i);
        r_commitments.push(r_i);

        let round_challenge = transcript.get_challenge::<C>(
            format!("IPA:round_challenge_{index}"),
        );
        u_challenges.push(round_challenge);
    }

    // Read final values
    let g_0 = transcript.receive_point_from_prover::<C>("IPA:G_0".to_string())
        .expect("G_0");
    let a_0 = transcript.receive_fr_from_prover::<C>("IPA:a_0".to_string())
        .expect("a_0");

    // Compute the folded b value: b₀ = Π (1 + u_i⁻¹ · β^{2^i})
    // Actually: b₀ is the evaluation of the challenge polynomial at β
    // b₀ = Π_i (1 + u_i⁻¹ · β^{2^{k-1-i}})...
    // Simpler: compute b₀ by folding the b vector the same way the prover did.
    let mut b_vec: Vec<C::ScalarField> = {
        let mut v = Vec::with_capacity(poly_length);
        let mut b_power = C::ScalarField::one();
        for _ in 0..poly_length {
            v.push(b_power);
            b_power *= challenge;
        }
        v
    };

    let mut round_size = poly_length;
    for u in &u_challenges {
        round_size /= 2;
        let u_inv = u.inverse().expect("challenge nonzero");
        let new_b: Vec<C::ScalarField> = (0..round_size)
            .map(|j| b_vec[j] + u_inv * b_vec[round_size + j])
            .collect();
        b_vec[..round_size].copy_from_slice(&new_b);
    }
    let b_0 = b_vec[0];

    // Step 5: C₀ = C' + Σ u_j⁻¹·L_j + Σ u_j·R_j
    // where C' = C + v·U
    let c_prime: C = C::from(commitment) + aux_generator * evaluation;

    let mut c_zero = c_prime;
    for i in 0..log_n {
        let u_inv = u_challenges[i].inverse().expect("challenge nonzero");
        c_zero += C::from(l_commitments[i]) * u_inv;
        c_zero += C::from(r_commitments[i]) * u_challenges[i];
    }

    // Step 8: Compute G_s from s-vector and CRS
    // s = (1, u₀⁻¹, u₁⁻¹, u₀⁻¹u₁⁻¹, ..., Π u_i⁻¹)
    let s_vec = construct_s_vector(&u_challenges);
    let g_s: C = C::msm_unchecked(&vk.generators[..poly_length], &s_vec);

    // Verify G_0 from prover matches our computed G_s
    // (bb asserts this; we check it)
    if g_s.into_affine() != g_0 {
        return false;
    }

    // Step 10: C_right = a₀·G_s + a₀·b₀·U
    let rhs: C = g_s * a_0 + aux_generator * (a_0 * b_0);

    // Step 11: Check C₀ == C_right
    c_zero == rhs
}
