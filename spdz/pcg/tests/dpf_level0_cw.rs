//! Level-0 correction-word compatibility test — the critical validation
//! that oblivious DPF gen is structurally sound.
//!
//! For a log_n=1 DPF, the trusted-dealer (`pcg_core::dpf::gen_dpf`)
//! produces:
//!   - `root_0`, `root_1` (per-party)
//!   - One correction word at level 0: `(cw_seed, cw_l, cw_r)`
//!   - A `final_correction`
//!
//! This test re-derives the SAME `(cw_seed, cw_l, cw_r)` via the 2-party
//! oblivious protocol described in `docs/OBLIVIOUS_DPF_GEN_DESIGN.md`:
//!
//!   1. Both parties hold `(my_alpha_share, my_beta_share)`.
//!   2. P0 picks `root_0`; P1 picks `root_1`.
//!   3. Joint state at level 0 represented as:
//!      - `seed_0_shared` = (P0: root_0, P1: 0)     # logical = root_0
//!      - `seed_1_shared` = (P0: 0,      P1: root_1) # logical = root_1
//!   4. Run `Prg2pcSession::expand` TWICE:
//!      - `prg_shares_0` = shares of `prg(root_0)`
//!      - `prg_shares_1` = shares of `prg(root_1)`
//!   5. Each party now has shares of:
//!      (s_0_L, s_0_R, t_0_L, t_0_R, s_1_L, s_1_R, t_1_L, t_1_R)
//!   6. Compute correction words via public XOR of shares + sec_and_block.
//!
//! Critical assertion: the 2-party-computed CWs match bit-for-bit the
//! trusted-dealer's CWs for the same (root_0, root_1, α).
//!
//! If this test passes, the design is correct at the correction-word layer
//! and we can extend to arbitrary log_n by implementing state advancement.
//!
//! Skipped pieces (for this level-0 test):
//!   - log_n>1 state advancement
//!   - final_correction (needs leaf hash / OLE)

#![cfg(feature = "gc")]

use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use pcg_core::dpf::{gen_dpf, prg as core_prg};
use pcg_core::pcg::Role;
use pcg_protocols::{sec_and_block, BitOt, MockBitOt};
use spdz_pcg::Prg2pcSession;
use std::sync::Arc;

use ark_bn254::Fr;

fn xor16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn make_delta() -> Block {
    // Shared delta for the POC (same simplification as other GC tests).
    let mut b = [0u8; 16];
    b[0] = 0x01;
    for (i, x) in b.iter_mut().enumerate().skip(1) {
        *x = 0x9F ^ (i as u8);
    }
    Block::new(b)
}

#[test]
fn level0_cw_matches_trusted_dealer_alpha0() {
    // Fix params. log_n=1, α=0, β=Fr::from(7).
    let log_n = 1u32;
    let alpha: u64 = 0;
    let beta = Fr::from(7u64);
    let rng_seed: u64 = 0xDEAD_BEEF;

    // --- Trusted-dealer reference ---
    let (k0_ref, _k1_ref) = gen_dpf::<Fr>(log_n, alpha, beta, rng_seed);
    let root_0 = k0_ref.root_seed;
    let (_k0_again, k1_ref_again) = gen_dpf::<Fr>(log_n, alpha, beta, rng_seed);
    let root_1 = k1_ref_again.root_seed;
    let expected_cw = &k0_ref.corrections[0];
    // Note: k1_ref's corrections are the same as k0_ref's (by construction).

    // --- 2-party α-share split: α=0 = 0⊕0 ---
    let alpha_0_share: bool = false;
    let alpha_1_share: bool = false;

    // --- 2-party execution ---
    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());

    // We use MockBitOt for sec_and_block; Prg2pcSession uses ideal_cot.
    let (ot0, ot1) = MockBitOt::new_pair();

    let net0_c = net0.clone();
    let net1_c = net1.clone();

    let h0 = std::thread::spawn(move || -> CWOutput {
        let mut prg = Prg2pcSession::new(net0_c, delta).unwrap();
        let mut ot = ot0;
        // P0's joint state at level 0:
        //   seed_0_shared P0-side = root_0,  P1-side = 0
        //   seed_1_shared P0-side = 0,       P1-side = root_1
        // We run two expands in SEQUENCE on P0's shares.
        let share_prg_root_0 = prg.expand(root_0).unwrap();
        let share_prg_root_1 = prg.expand([0u8; 16]).unwrap();
        oblivious_cw_level_0(
            &mut ot,
            Role::P0,
            alpha_0_share,
            share_prg_root_0.s_l,
            share_prg_root_0.s_r,
            share_prg_root_1.s_l,
            share_prg_root_1.s_r,
        )
        .unwrap()
    });
    let h1 = std::thread::spawn(move || -> CWOutput {
        let mut prg = Prg2pcSession::new(net1_c, delta).unwrap();
        let mut ot = ot1;
        // P1 runs expand on its own shares, in the SAME order as P0
        // (keeps lock-step with prg.expand internally):
        let share_prg_root_0 = prg.expand([0u8; 16]).unwrap();
        let share_prg_root_1 = prg.expand(root_1).unwrap();
        oblivious_cw_level_0(
            &mut ot,
            Role::P1,
            alpha_1_share,
            share_prg_root_0.s_l,
            share_prg_root_0.s_r,
            share_prg_root_1.s_l,
            share_prg_root_1.s_r,
        )
        .unwrap()
    });

    let out_0 = h0.join().unwrap();
    let out_1 = h1.join().unwrap();

    // Both parties should see the same (public) CW values.
    assert_eq!(out_0.cw_seed, out_1.cw_seed, "cw_seed: P0/P1 disagree");
    assert_eq!(out_0.cw_tl, out_1.cw_tl, "cw_tL: P0/P1 disagree");
    assert_eq!(out_0.cw_tr, out_1.cw_tr, "cw_tR: P0/P1 disagree");

    // And they must match the trusted-dealer reference.
    assert_eq!(out_0.cw_seed, expected_cw.cw_seed, "cw_seed != trusted-dealer");
    assert_eq!(out_0.cw_tl, expected_cw.cw_l, "cw_tL != trusted-dealer");
    assert_eq!(out_0.cw_tr, expected_cw.cw_r, "cw_tR != trusted-dealer");

    // Sanity: verify plaintext prg agrees with what we think it does
    let (s_0_l, _t_0_l, s_0_r, _t_0_r) = core_prg(root_0);
    let (s_1_l, _t_1_l, s_1_r, _t_1_r) = core_prg(root_1);
    // For α=0: lose side = R
    let expected_cw_seed = xor16(s_0_r, s_1_r);
    assert_eq!(
        expected_cw.cw_seed, expected_cw_seed,
        "sanity: dealer's cw_seed formula check"
    );
    // our s_0_l, s_0_r check: matches PRG
    let _ = (s_0_l, s_1_l);
}

#[test]
fn level0_cw_matches_trusted_dealer_alpha1() {
    // α=1 now. Tests the other branch.
    let log_n = 1u32;
    let alpha: u64 = 1;
    let beta = Fr::from(99u64);
    let rng_seed: u64 = 0xC0FE_FEED;

    let (k0_ref, _) = gen_dpf::<Fr>(log_n, alpha, beta, rng_seed);
    let root_0 = k0_ref.root_seed;
    let (_, k1_ref) = gen_dpf::<Fr>(log_n, alpha, beta, rng_seed);
    let root_1 = k1_ref.root_seed;
    let expected_cw = &k0_ref.corrections[0];

    // α=1 = 1⊕0
    let alpha_0_share = true;
    let alpha_1_share = false;

    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    let h0 = std::thread::spawn(move || -> CWOutput {
        let mut prg = Prg2pcSession::new(net0, delta).unwrap();
        let mut ot = ot0;
        let share_prg_root_0 = prg.expand(root_0).unwrap();
        let share_prg_root_1 = prg.expand([0u8; 16]).unwrap();
        oblivious_cw_level_0(
            &mut ot,
            Role::P0,
            alpha_0_share,
            share_prg_root_0.s_l,
            share_prg_root_0.s_r,
            share_prg_root_1.s_l,
            share_prg_root_1.s_r,
        )
        .unwrap()
    });
    let h1 = std::thread::spawn(move || -> CWOutput {
        let mut prg = Prg2pcSession::new(net1, delta).unwrap();
        let mut ot = ot1;
        let share_prg_root_0 = prg.expand([0u8; 16]).unwrap();
        let share_prg_root_1 = prg.expand(root_1).unwrap();
        oblivious_cw_level_0(
            &mut ot,
            Role::P1,
            alpha_1_share,
            share_prg_root_0.s_l,
            share_prg_root_0.s_r,
            share_prg_root_1.s_l,
            share_prg_root_1.s_r,
        )
        .unwrap()
    });

    let out_0 = h0.join().unwrap();
    let out_1 = h1.join().unwrap();

    assert_eq!(out_0.cw_seed, out_1.cw_seed);
    assert_eq!(out_0.cw_tl, out_1.cw_tl);
    assert_eq!(out_0.cw_tr, out_1.cw_tr);
    assert_eq!(out_0.cw_seed, expected_cw.cw_seed, "α=1: cw_seed mismatch");
    assert_eq!(out_0.cw_tl, expected_cw.cw_l, "α=1: cw_tL mismatch");
    assert_eq!(out_0.cw_tr, expected_cw.cw_r, "α=1: cw_tR mismatch");

    // Silence unused when α=1
    let _ = beta;
}

#[derive(Debug, Clone, Copy)]
struct CWOutput {
    cw_seed: [u8; 16],
    cw_tl: bool,
    cw_tr: bool,
}

/// 2-party oblivious computation of (cw_seed, cw_tL, cw_tR) at level 0 of
/// a DPF, given XOR-shares of PRG outputs and α.
///
/// Inputs (per party):
///   - `alpha_share`: party's XOR-share of α_0 (the MSB of α for log_n=1).
///   - `s_0_l_share`, `s_0_r_share`: party's XOR-shares of P0's tree's
///     level-1 children under PRG(root_0).
///   - `s_1_l_share`, `s_1_r_share`: party's XOR-shares of P1's tree's
///     level-1 children under PRG(root_1).
///
/// Output:
///   - `cw_seed = s_0_lose ⊕ s_1_lose`  (public 128 bits)
///   - `cw_tL = t_0_l ⊕ t_1_l ⊕ ¬α`     (public 1 bit)
///   - `cw_tR = t_0_r ⊕ t_1_r ⊕ α`      (public 1 bit)
///
/// where `t_b_side = LSB(s_b_side)`.
fn oblivious_cw_level_0<OT: BitOt>(
    ot: &mut OT,
    role: Role,
    alpha_share: bool,
    s_0_l_share: [u8; 16],
    s_0_r_share: [u8; 16],
    s_1_l_share: [u8; 16],
    s_1_r_share: [u8; 16],
) -> eyre::Result<CWOutput> {
    // Control bits: LSB of each seed share.
    let t_0_l_share = s_0_l_share[0] & 1 == 1;
    let t_0_r_share = s_0_r_share[0] & 1 == 1;
    let t_1_l_share = s_1_l_share[0] & 1 == 1;
    let t_1_r_share = s_1_r_share[0] & 1 == 1;

    // ---- cw_tL = t_0_l ⊕ t_1_l ⊕ ¬α = t_0_l ⊕ t_1_l ⊕ α ⊕ 1 ----
    // Each party's contribution: t_0_l_share ⊕ t_1_l_share ⊕ alpha_share ⊕ (1 if P0 else 0)
    let my_cw_tl_contrib = t_0_l_share
        ^ t_1_l_share
        ^ alpha_share
        ^ matches!(role, Role::P0);
    ot.reveal_bit(my_cw_tl_contrib)?;
    let peer_cw_tl_contrib = ot.recv_revealed_bit()?;
    let cw_tl = my_cw_tl_contrib ^ peer_cw_tl_contrib;

    // ---- cw_tR = t_0_r ⊕ t_1_r ⊕ α ----
    let my_cw_tr_contrib = t_0_r_share ^ t_1_r_share ^ alpha_share;
    ot.reveal_bit(my_cw_tr_contrib)?;
    let peer_cw_tr_contrib = ot.recv_revealed_bit()?;
    let cw_tr = my_cw_tr_contrib ^ peer_cw_tr_contrib;

    // ---- cw_seed = s_0_lose ⊕ s_1_lose ----
    // s_b_lose = s_b_R if α=0 else s_b_L. I.e. s_b_R ⊕ α·(s_b_L ⊕ s_b_R).
    // Compute per-party XOR-share of s_b_lose for b = 0, 1.

    // For b = 0:
    let diff_0_share = xor16(s_0_l_share, s_0_r_share);
    let alpha_diff_0_share = sec_and_block(ot, role, alpha_share, diff_0_share)?;
    let s_0_lose_share = xor16(s_0_r_share, alpha_diff_0_share);

    // For b = 1:
    let diff_1_share = xor16(s_1_l_share, s_1_r_share);
    let alpha_diff_1_share = sec_and_block(ot, role, alpha_share, diff_1_share)?;
    let s_1_lose_share = xor16(s_1_r_share, alpha_diff_1_share);

    // cw_seed_share = s_0_lose_share ⊕ s_1_lose_share (local XOR of XOR-shares)
    let my_cw_seed_share = xor16(s_0_lose_share, s_1_lose_share);
    ot.reveal_block(my_cw_seed_share)?;
    let peer_cw_seed_share = ot.recv_revealed_block()?;
    let cw_seed = xor16(my_cw_seed_share, peer_cw_seed_share);

    Ok(CWOutput { cw_seed, cw_tl, cw_tr })
}
