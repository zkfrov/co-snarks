//! Distributed Point Function (DPF) over BN254 Fr.
//!
//! A DPF encodes a "point function" f: [N] → F where f(α) = β, f(x) = 0 otherwise.
//! The function is split into two keys k_0, k_1 such that:
//!
//!   f(x) = Eval(k_0, x) + Eval(k_1, x)    for all x in [N]
//!
//! Each key is O(log N · λ) bytes, much smaller than the O(N) full vector.
//!
//! Construction (GGM tree):
//! - The domain [N] with N = 2^d is the leaves of a binary tree of depth d.
//! - Each tree node holds a 128-bit seed + a 1-bit control flag.
//! - At each level, children are computed via a PRG on the seed.
//! - One "correction word" is published per level, shared between the parties.
//!   The party whose control bit is 1 applies the correction to its child;
//!   the other doesn't.
//! - At the leaves, nodes are mapped to F via hash, then adjusted by a final
//!   correction so that position α outputs β.
//!
//! This module provides:
//! - `DpfKey<F>`: the per-party key
//! - `gen_dpf`: trusted-dealer key generation (MVP; real 2-party version
//!   comes in Phase 2b.1)
//! - `eval_all`: expand a key to the full length-N vector
//!
//! Reference: Boyle, Gilboa, Ishai "Function Secret Sharing" (Eurocrypt 2015).

use ark_ff::PrimeField;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// A 128-bit seed value (tree node).
pub type Seed = [u8; 16];

/// DPF key held by one party.
#[derive(Clone, Debug)]
pub struct DpfKey<F: PrimeField> {
    /// Log2 of the domain size. Domain is [0, 2^log_n).
    pub log_n: u32,
    /// This party's initial seed (root node).
    pub root_seed: Seed,
    /// Initial control bit (0 or 1).
    pub root_ctrl: bool,
    /// Correction words: one per tree level (there are `log_n` of them).
    /// Each has two components:
    ///   - `cw_seed`: the seed correction for this level
    ///   - `cw_l`, `cw_r`: left/right control-bit corrections
    pub corrections: Vec<CorrectionWord>,
    /// Final correction applied at the leaf to get the point value β at α.
    pub final_correction: F,
    /// Which party this key is for (0 or 1). Used for sign-flipping final outputs.
    pub party: u8,
}

#[derive(Clone, Debug)]
pub struct CorrectionWord {
    pub cw_seed: Seed,
    pub cw_l: bool,
    pub cw_r: bool,
}

/// PRG: 16-byte seed → 16-byte child seed + 1 control bit, for both children.
///
/// Uses ChaCha20 as the PRG (AES-based variants are faster but this is a
/// clean-Rust MVP; can be swapped later for AES-NI if performance demands).
/// Layout of 40 bytes output: [L_seed(16)][L_ctrl(1 byte → lsb)][R_seed(16)][R_ctrl(1 byte → lsb)] + 6 bytes discarded.
fn prg(seed: Seed) -> (Seed, bool, Seed, bool) {
    // Seed the ChaCha with `seed` (using it as the 32-byte seed by duplicating).
    let mut seed32 = [0u8; 32];
    seed32[..16].copy_from_slice(&seed);
    seed32[16..].copy_from_slice(&seed);
    let mut rng = ChaCha20Rng::from_seed(seed32);
    let mut left_seed = [0u8; 16];
    let mut right_seed = [0u8; 16];
    rng.fill(&mut left_seed);
    rng.fill(&mut right_seed);
    let l_ctrl: u8 = rng.r#gen();
    let r_ctrl: u8 = rng.r#gen();
    (left_seed, (l_ctrl & 1) == 1, right_seed, (r_ctrl & 1) == 1)
}

fn xor_seed(a: &Seed, b: &Seed) -> Seed {
    let mut out = *a;
    for i in 0..16 {
        out[i] ^= b[i];
    }
    out
}

/// Hash a seed (post-expansion leaf node) to a field element.
fn seed_to_field<F: PrimeField>(seed: Seed, tag: u64) -> F {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"DPF-LEAF\x00");
    hasher.update(tag.to_le_bytes());
    hasher.update(seed);
    let digest = hasher.finalize();
    F::from_le_bytes_mod_order(&digest)
}

/// Trusted-dealer DPF key generation.
///
/// Produces a pair of keys (k0, k1) for a point function f(x) = β if x = α, else 0.
/// A dealer generates both keys and sends each one to the corresponding party
/// (no cryptographic communication simulated here — this is MVP).
pub fn gen_dpf<F: PrimeField>(
    log_n: u32,
    alpha: u64,
    beta: F,
    rng_seed: u64,
) -> (DpfKey<F>, DpfKey<F>) {
    assert!(log_n as u64 <= 64, "log_n must fit in u64");
    assert!(alpha < 1u64 << log_n, "alpha must be in [0, 2^log_n)");

    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);

    // Initial seeds are uniformly random and different between parties.
    let mut s0: Seed = [0u8; 16];
    let mut s1: Seed = [0u8; 16];
    rng.fill(&mut s0);
    rng.fill(&mut s1);

    // Initial control bits: 0 for party 0, 1 for party 1.
    let mut t0 = false;
    let mut t1 = true;

    let mut corrections: Vec<CorrectionWord> = Vec::with_capacity(log_n as usize);
    let mut s0_cur = s0;
    let mut s1_cur = s1;
    let mut t0_cur = t0;
    let mut t1_cur = t1;

    for i in 0..log_n {
        // α_i = the (i+1)-th msb of α (we descend from msb to lsb).
        let alpha_i = ((alpha >> (log_n - 1 - i)) & 1) == 1;

        // Expand both parties' current seeds via PRG.
        let (s0_l, t0_l, s0_r, t0_r) = prg(s0_cur);
        let (s1_l, t1_l, s1_r, t1_r) = prg(s1_cur);

        // Pick the "keep" side (the one matching α_i) and "lose" side.
        let (s0_keep, t0_keep, s0_lose, t0_lose) = if alpha_i {
            (s0_r, t0_r, s0_l, t0_l)
        } else {
            (s0_l, t0_l, s0_r, t0_r)
        };
        let (s1_keep, t1_keep, s1_lose, t1_lose) = if alpha_i {
            (s1_r, t1_r, s1_l, t1_l)
        } else {
            (s1_l, t1_l, s1_r, t1_r)
        };

        // The correction word is designed so that:
        //   Party 0 and Party 1 arrive at DIFFERENT seeds on the α-path and
        //   IDENTICAL seeds on the off-α-path.
        //   After combining at the leaf, off-α paths cancel (same seed → same field elt).
        let cw_seed = xor_seed(&s0_lose, &s1_lose);
        let cw_l = t0_l ^ t1_l ^ alpha_i ^ true; // want t=1 on lose side so both apply corrections
        let cw_r = t0_r ^ t1_r ^ alpha_i;

        // Apply correction word to advance to the next level.
        // Party 0 applies correction iff its CURRENT control bit is 1; same for P1.
        let apply_p0 = t0_cur;
        let apply_p1 = t1_cur;

        let (s0_next, t0_l_new, t0_r_new) = if apply_p0 {
            (xor_seed(&s0_keep, &cw_seed), t0_l ^ cw_l, t0_r ^ cw_r)
        } else {
            (s0_keep, t0_l, t0_r)
        };
        let (s1_next, t1_l_new, t1_r_new) = if apply_p1 {
            (xor_seed(&s1_keep, &cw_seed), t1_l ^ cw_l, t1_r ^ cw_r)
        } else {
            (s1_keep, t1_l, t1_r)
        };

        // Pick the control bit corresponding to α_i.
        let t0_next = if alpha_i { t0_r_new } else { t0_l_new };
        let t1_next = if alpha_i { t1_r_new } else { t1_l_new };

        corrections.push(CorrectionWord {
            cw_seed,
            cw_l,
            cw_r,
        });

        s0_cur = s0_next;
        s1_cur = s1_next;
        t0_cur = t0_next;
        t1_cur = t1_next;

        // keep lint-style silence on unused-after-shadow warnings
        let _ = (
            s0_lose, t0_lose, s1_lose, t1_lose, s0_keep, t0_keep, s1_keep, t1_keep,
        );
    }

    // Final correction: set position α to β. Each party will hash its final
    // seed to a field element; their sum should equal β at α.
    let tag = alpha;
    let f0_at_alpha = seed_to_field::<F>(s0_cur, tag);
    let f1_at_alpha = seed_to_field::<F>(s1_cur, tag);
    // Party 0 computes: +f0. Party 1 computes: -f1. So sum = f0 - f1. We want β.
    // Thus final_correction = β - (f0 - f1). Party 0 adds it, party 1 doesn't
    // — but to keep symmetry, we give BOTH parties the same final_correction
    // and they both add it, with party 1 adding with sign flip.
    // Simpler: f0 - f1 + correction * (t0 - t1) at the α leaf. Set:
    //   correction = β - (f0 - f1)  if t0_cur != t1_cur at α leaf.
    // The construction ensures t0_cur != t1_cur at α leaf (since we started
    // with t0=false, t1=true and the corrections preserve this on-path).
    debug_assert_ne!(t0_cur, t1_cur, "on-α-path control bits must differ");
    // Output convention:
    //   Output_P0(x) = +(H(s0_leaf) + t0_leaf · CW)
    //   Output_P1(x) = -(H(s1_leaf) + t1_leaf · CW)
    //
    // At α: sum = (H(s0) - H(s1)) + (t0 - t1)·CW. We want this = β.
    // Since t0, t1 ∈ {0,1} differ on α: (t0 - t1) ∈ {+1, -1}.
    //
    // If t0=false, t1=true: (t0 - t1) = -1
    //   → CW = H(s0) - H(s1) - β
    // If t0=true, t1=false: (t0 - t1) = +1
    //   → CW = β - H(s0) + H(s1)
    let final_correction = if !t0_cur && t1_cur {
        f0_at_alpha - f1_at_alpha - beta
    } else {
        beta - f0_at_alpha + f1_at_alpha
    };

    let k0 = DpfKey {
        log_n,
        root_seed: s0,
        root_ctrl: t0,
        corrections: corrections.clone(),
        final_correction,
        party: 0,
    };
    let k1 = DpfKey {
        log_n,
        root_seed: s1,
        root_ctrl: t1,
        corrections,
        final_correction,
        party: 1,
    };
    let _ = (t0_cur, t1_cur);
    (k0, k1)
}

/// Evaluate all 2^log_n points of the DPF, returning a length-N vector.
pub fn eval_all<F: PrimeField>(key: &DpfKey<F>) -> Vec<F> {
    let n = 1usize << key.log_n;
    // Level-0: one node with (root_seed, root_ctrl).
    let mut cur_seeds: Vec<Seed> = vec![key.root_seed];
    let mut cur_ctrls: Vec<bool> = vec![key.root_ctrl];

    for i in 0..key.log_n as usize {
        let cw = &key.corrections[i];
        let mut next_seeds: Vec<Seed> = Vec::with_capacity(cur_seeds.len() * 2);
        let mut next_ctrls: Vec<bool> = Vec::with_capacity(cur_ctrls.len() * 2);

        for (s, t) in cur_seeds.iter().zip(cur_ctrls.iter()) {
            let (s_l, t_l, s_r, t_r) = prg(*s);
            let (new_s_l, new_t_l, new_s_r, new_t_r) = if *t {
                // Apply correction
                (
                    xor_seed(&s_l, &cw.cw_seed),
                    t_l ^ cw.cw_l,
                    xor_seed(&s_r, &cw.cw_seed),
                    t_r ^ cw.cw_r,
                )
            } else {
                (s_l, t_l, s_r, t_r)
            };
            next_seeds.push(new_s_l);
            next_ctrls.push(new_t_l);
            next_seeds.push(new_s_r);
            next_ctrls.push(new_t_r);
        }

        cur_seeds = next_seeds;
        cur_ctrls = next_ctrls;
    }

    debug_assert_eq!(cur_seeds.len(), n);
    debug_assert_eq!(cur_ctrls.len(), n);

    // Leaf: output = party_sign * (hash(seed) + ctrl * final_correction)
    let sign = if key.party == 0 { F::one() } else { -F::one() };
    let mut out = Vec::with_capacity(n);
    for (x, (s, t)) in cur_seeds.iter().zip(cur_ctrls.iter()).enumerate() {
        let h = seed_to_field::<F>(*s, x as u64);
        let mut v = h;
        if *t {
            v += key.final_correction;
        }
        out.push(sign * v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};

    fn combine(v0: &[Fr], v1: &[Fr]) -> Vec<Fr> {
        v0.iter().zip(v1.iter()).map(|(a, b)| *a + *b).collect()
    }

    #[test]
    fn dpf_point_function_log8() {
        let log_n = 8u32;
        let alpha = 42u64;
        let beta = Fr::from(777u64);
        let (k0, k1) = gen_dpf::<Fr>(log_n, alpha, beta, 0xC0FFEE);

        let v0 = eval_all(&k0);
        let v1 = eval_all(&k1);
        let combined = combine(&v0, &v1);

        // At position α: sum should be β.
        assert_eq!(combined[alpha as usize], beta, "value at α incorrect");

        // At every other position: sum should be 0.
        for (i, v) in combined.iter().enumerate() {
            if i == alpha as usize {
                continue;
            }
            assert_eq!(
                *v,
                Fr::zero(),
                "position {i} should be zero but is non-zero"
            );
        }
    }

    #[test]
    fn dpf_random_points_log12() {
        // Larger domain (2^12 = 4096) with random α and β.
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(99);
        use ark_ff::UniformRand;
        use rand::Rng;
        for trial in 0..8 {
            let alpha: u64 = rng.r#gen::<u64>() % (1 << 12);
            let beta = Fr::rand(&mut rng);
            let rng_seed: u64 = rng.r#gen();
            let (k0, k1) = gen_dpf::<Fr>(12, alpha, beta, rng_seed);
            let v0 = eval_all(&k0);
            let v1 = eval_all(&k1);
            assert_eq!(v0.len(), 4096);
            let combined = combine(&v0, &v1);
            assert_eq!(combined[alpha as usize], beta, "trial {trial} α={alpha}");
            for (i, v) in combined.iter().enumerate() {
                if i != alpha as usize {
                    assert_eq!(*v, Fr::zero(), "trial {trial} i={i}");
                }
            }
        }
    }

    #[test]
    fn dpf_zero_at_boundaries() {
        for alpha in &[0u64, 1, 127, 255] {
            let (k0, k1) = gen_dpf::<Fr>(8, *alpha, Fr::one(), 0xABCD);
            let v0 = eval_all(&k0);
            let v1 = eval_all(&k1);
            let c = combine(&v0, &v1);
            for (i, v) in c.iter().enumerate() {
                if i == *alpha as usize {
                    assert_eq!(*v, Fr::one(), "α={alpha} pos α wrong");
                } else {
                    assert_eq!(*v, Fr::zero(), "α={alpha} pos {i} wrong");
                }
            }
        }
    }
}
