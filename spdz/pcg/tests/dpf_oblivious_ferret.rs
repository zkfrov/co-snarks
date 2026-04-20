//! End-to-end oblivious DPF gen over **Ferret-backed** Prg2pcSession.
//!
//! Upgrade over `dpf_oblivious_lib.rs`: the garbled-circuit COT is now
//! backed by Ferret silent OT (`DerandCOTSender(FerretSender)`) instead
//! of `ideal_cot`. This closes the last production-readiness gap of
//! oblivious DPF gen — the previous POCs used `ideal_cot` with a shared delta,
//! which is insecure because both parties know delta.
//!
//! ## Performance caveat
//!
//! Each `Prg2pcSession::expand` call currently does a fresh Ferret LPN
//! bootstrap (~5s). For a log_n=N DPF, this means 2N bootstraps —
//! impractical for large N. This test uses log_n=2 (4 bootstraps per
//! DPF) to keep runtime reasonable.
//!
//! The production path is to maintain a persistent Ferret session
//! across multiple expand calls, bringing per-expand cost down to sub-
//! ms (just the actual GC circuit work). Documented as the next
//! optimization step in `OBLIVIOUS_DPF_GEN_DESIGN.md`.
//!
//! ## What this validates
//!
//! - `Prg2pcSession::new_ferret` produces correct PRG outputs
//! - `DerandCOTSender/Receiver` wraps `FerretSender/Receiver` correctly
//!   for garbling
//! - End-to-end `dpf_gen_oblivious` produces valid DPF keys with
//!   Ferret-backed OT

#![cfg(feature = "gc")]

use ark_bn254::Fr;
use ark_ff::UniformRand;
use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use pcg_core::dpf::{eval_all, gen_dpf};
use pcg_core::pcg::Role;
use pcg_protocols::MockBitOt;
use rand::SeedableRng;
use spdz_pcg::{dpf_gen_oblivious, Prg2pcSession};
use std::sync::Arc;

fn make_delta() -> Block {
    let mut b = [0u8; 16];
    b[0] = 0x01;
    for (i, x) in b.iter_mut().enumerate().skip(1) {
        *x = 0x9F ^ (i as u8);
    }
    Block::new(b)
}

#[test]
fn dpf_gen_oblivious_ferret_backed_log_n_2() {
    let log_n = 2u32;
    let alpha = 2u64;
    let seed = 0x7E57_F00D;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let beta = Fr::rand(&mut rng);

    let (k0_ref, k1_ref) = gen_dpf::<Fr>(log_n, alpha, beta, seed);
    let root_0 = k0_ref.root_seed;
    let root_1 = k1_ref.root_seed;

    // α splits: α = α_0 ⊕ α_1 = α_0 ⊕ 0 = α.
    let alpha_0 = alpha;
    let alpha_1 = 0u64;
    let beta_0 = Fr::rand(&mut rng);
    let beta_1 = beta - beta_0;

    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    let h0 = std::thread::spawn(move || {
        // KEY DIFFERENCE: new_ferret instead of new
        let mut prg = Prg2pcSession::new_ferret(net0, delta).unwrap();
        let mut ot = ot0;
        dpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P0, alpha_0, beta_0, root_0, log_n,
        )
        .unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net1, delta).unwrap();
        let mut ot = ot1;
        dpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P1, alpha_1, beta_1, root_1, log_n,
        )
        .unwrap()
    });
    let k0 = h0.join().unwrap();
    let k1 = h1.join().unwrap();

    // Verify the Ferret-backed gen produces the same keys as trusted-dealer
    // (correction words + final_correction).
    assert_eq!(k0.root_seed, k0_ref.root_seed);
    assert_eq!(k1.root_seed, k1_ref.root_seed);
    for (i, (got, exp)) in k0.corrections.iter().zip(k0_ref.corrections.iter()).enumerate() {
        assert_eq!(got.cw_seed, exp.cw_seed, "lvl {i} cw_seed");
        assert_eq!(got.cw_l, exp.cw_l, "lvl {i} cw_l");
        assert_eq!(got.cw_r, exp.cw_r, "lvl {i} cw_r");
    }
    assert_eq!(k0.final_correction, k0_ref.final_correction);

    // Semantic: eval_all gives the point function.
    let v0 = eval_all(&k0);
    let v1 = eval_all(&k1);
    for (i, (a, b)) in v0.iter().zip(v1.iter()).enumerate() {
        let sum = *a + *b;
        if i == alpha as usize {
            assert_eq!(sum, beta, "α={alpha}: sum at α mismatch");
        } else {
            assert_eq!(sum, Fr::from(0u64), "α={alpha}: off-path {i} nonzero");
        }
    }
}
