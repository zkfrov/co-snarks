//! Integration tests for `spdz_pcg::dpf_gen_oblivious` — the public
//! library API for oblivious 2-party DPF generation.
//!
//! Validates that:
//!   - Keys produced match `pcg_core::dpf::gen_dpf` (trusted-dealer)
//!     bit-for-bit when given the same roots + α + β (corrections and
//!     final_correction both match).
//!   - `pcg_core::dpf::eval_all` on the produced keys gives the correct
//!     point function `f(α) = β, f(x) = 0 otherwise`.
//!   - No seeds, ctrl bits, or α shares are revealed during gen
//!     (enforced implicitly — the only `BitOt` operations used are
//!     sec_and, sec_and_block, block-OT reveals of CW contributions,
//!     and bit-OT with field messages for the leaf).

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

/// Drive both parties through `dpf_gen_oblivious` with matched setup.
fn run_oblivious_gen(
    log_n: u32,
    alpha: u64,
    beta: Fr,
    rng_seed: u64,
) -> (
    pcg_core::dpf::DpfKey<Fr>,
    pcg_core::dpf::DpfKey<Fr>,
    pcg_core::dpf::DpfKey<Fr>,
    pcg_core::dpf::DpfKey<Fr>,
) {
    // Trusted-dealer reference.
    let (k0_ref, k1_ref) = gen_dpf::<Fr>(log_n, alpha, beta, rng_seed);
    let root_0 = k0_ref.root_seed;
    let root_1 = k1_ref.root_seed;

    // Splits
    let alpha_0 = alpha;
    let alpha_1 = 0u64;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(rng_seed ^ 0xBEEF);
    let beta_0 = Fr::rand(&mut rng);
    let beta_1 = beta - beta_0;

    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    let h0 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new(net0, delta).unwrap();
        let mut ot = ot0;
        dpf_gen_oblivious::<Fr, _, _>(&mut prg, &mut ot, Role::P0, alpha_0, beta_0, root_0, log_n)
            .unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new(net1, delta).unwrap();
        let mut ot = ot1;
        dpf_gen_oblivious::<Fr, _, _>(&mut prg, &mut ot, Role::P1, alpha_1, beta_1, root_1, log_n)
            .unwrap()
    });
    let k0 = h0.join().unwrap();
    let k1 = h1.join().unwrap();
    (k0, k1, k0_ref, k1_ref)
}

#[test]
fn dpf_gen_oblivious_matches_trusted_dealer_log_n_2() {
    for alpha in 0u64..4 {
        let seed = 0x7E57 + alpha;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let beta = Fr::rand(&mut rng);
        let (k0, k1, k0_ref, k1_ref) = run_oblivious_gen(2, alpha, beta, seed);

        assert_eq!(k0.root_seed, k0_ref.root_seed);
        assert_eq!(k1.root_seed, k1_ref.root_seed);
        for (i, (got, exp)) in k0.corrections.iter().zip(k0_ref.corrections.iter()).enumerate() {
            assert_eq!(got.cw_seed, exp.cw_seed, "α={alpha} lvl {i} cw_seed");
            assert_eq!(got.cw_l, exp.cw_l, "α={alpha} lvl {i} cw_l");
            assert_eq!(got.cw_r, exp.cw_r, "α={alpha} lvl {i} cw_r");
        }
        assert_eq!(k0.final_correction, k0_ref.final_correction);
        assert_eq!(k1.final_correction, k1_ref.final_correction);
    }
}

#[test]
fn dpf_gen_oblivious_produces_point_function_log_n_3() {
    for (seed, alpha) in [(0x1111, 0), (0x2222, 3), (0x3333, 5), (0x4444, 7)] {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let beta = Fr::rand(&mut rng);
        let (k0, k1, _, _) = run_oblivious_gen(3, alpha, beta, seed);
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
}

#[test]
fn dpf_gen_oblivious_produces_point_function_log_n_4() {
    // log_n=4: 4 levels of state advancement. Catches any bugs that only
    // manifest at depth > 3.
    let log_n = 4u32;
    for alpha in [0u64, 1, 7, 15] {
        let seed = 0xA0A0 + alpha;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let beta = Fr::rand(&mut rng);
        let (k0, k1, _, _) = run_oblivious_gen(log_n, alpha, beta, seed);
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
}
