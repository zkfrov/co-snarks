//! End-to-end test for `Prg2pcSession`.
//!
//! Validates:
//!   - A session can be reused across multiple `expand` calls
//!   - Each call produces XOR-shares that reconstruct to the plaintext PRG
//!   - Control-bit extraction (`PrgShare::t_l` / `t_r`) is consistent

#![cfg(feature = "gc")]

use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use pcg_core::dpf::prg as core_prg;
use pcg_core::pcg::Role;
use spdz_pcg::{PrgShare, Prg2pcSession};
use std::sync::Arc;

fn xor16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Reference PRG — calls pcg-core's production `prg` function directly.
/// This is the *same* function that `pcg_core::dpf::gen_dpf` and `eval_all` use,
/// so matching it means our oblivious gen will produce trusted-dealer-compatible
/// keys.
fn plaintext_prg(seed: [u8; 16]) -> ([u8; 16], [u8; 16]) {
    let (s_l, _t_l, s_r, _t_r) = core_prg(seed);
    (s_l, s_r)
}

/// Reusable helper: run a closure on each party (P0 + P1) in its own thread
/// with its own Prg2pcSession over a shared LocalNetwork.
fn spawn_session_pair<F0, F1, R0, R1>(delta: Block, f0: F0, f1: F1) -> (R0, R1)
where
    F0: FnOnce(Prg2pcSession<LocalNetwork>) -> R0 + Send + 'static,
    F1: FnOnce(Prg2pcSession<LocalNetwork>) -> R1 + Send + 'static,
    R0: Send + 'static,
    R1: Send + 'static,
{
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let h0 = std::thread::spawn(move || {
        let sess = Prg2pcSession::new(net0, delta).unwrap();
        f0(sess)
    });
    let h1 = std::thread::spawn(move || {
        let sess = Prg2pcSession::new(net1, delta).unwrap();
        f1(sess)
    });
    (h0.join().unwrap(), h1.join().unwrap())
}

fn make_delta() -> Block {
    // Shared delta (POC). LSB set per GC convention.
    let mut b = [0u8; 16];
    b[0] = 0x01;
    for (i, x) in b.iter_mut().enumerate().skip(1) {
        *x = 0x9F ^ (i as u8);
    }
    Block::new(b)
}

#[test]
fn single_expand_matches_plaintext() {
    let seed_0: [u8; 16] = [0x42; 16];
    let seed_1: [u8; 16] = [0xBD; 16];
    let seed_true = xor16(seed_0, seed_1);
    let (exp_l, exp_r) = plaintext_prg(seed_true);

    let (share_0, share_1) = spawn_session_pair(
        make_delta(),
        move |mut sess| {
            assert_eq!(sess.role(), Role::P0);
            sess.expand(seed_0).unwrap()
        },
        move |mut sess| {
            assert_eq!(sess.role(), Role::P1);
            sess.expand(seed_1).unwrap()
        },
    );

    assert_eq!(xor16(share_0.s_l, share_1.s_l), exp_l);
    assert_eq!(xor16(share_0.s_r, share_1.s_r), exp_r);
    // Control-bit shares XOR to the plaintext LSB.
    assert_eq!(share_0.t_l() ^ share_1.t_l(), exp_l[0] & 1 == 1);
    assert_eq!(share_0.t_r() ^ share_1.t_r(), exp_r[0] & 1 == 1);
}

#[test]
fn session_reuse_across_multiple_expands() {
    // Simulate a DPF gen's inner loop: many expands on the same session.
    // Verifies the session state doesn't get corrupted between calls
    // (e.g., network buffer leftover, mpz state reuse, etc.).
    //
    // Number of rounds kept small so test runs in a reasonable time —
    // each expand creates a fresh Garbler/Evaluator so this is essentially
    // a stress-test of sequential session reuse rather than mpz-state
    // reuse.
    const ROUNDS: usize = 3;

    let seeds_0: Vec<[u8; 16]> = (0..ROUNDS).map(|i| [i as u8; 16]).collect();
    let seeds_1: Vec<[u8; 16]> = (0..ROUNDS).map(|i| [(i as u8) ^ 0xFF; 16]).collect();
    let seeds_0_clone = seeds_0.clone();
    let seeds_1_clone = seeds_1.clone();

    let (shares_0, shares_1) = spawn_session_pair(
        make_delta(),
        move |mut sess| -> Vec<PrgShare> {
            seeds_0_clone.iter().map(|s| sess.expand(*s).unwrap()).collect()
        },
        move |mut sess| -> Vec<PrgShare> {
            seeds_1_clone.iter().map(|s| sess.expand(*s).unwrap()).collect()
        },
    );

    assert_eq!(shares_0.len(), ROUNDS);
    assert_eq!(shares_1.len(), ROUNDS);
    for (i, (sh0, sh1)) in shares_0.iter().zip(shares_1.iter()).enumerate() {
        let seed_true = xor16(seeds_0[i], seeds_1[i]);
        let (exp_l, exp_r) = plaintext_prg(seed_true);
        assert_eq!(xor16(sh0.s_l, sh1.s_l), exp_l, "round {i} L");
        assert_eq!(xor16(sh0.s_r, sh1.s_r), exp_r, "round {i} R");
    }
}
