//! Release-mode benchmark for the full oblivious DPF gen pipeline.
//!
//! Measures the end-to-end time for `dpf_gen_oblivious` at different log_n,
//! with the Ferret-backed Prg2pcSession and persistent Garbler optimization.

#![cfg(feature = "gc")]

use ark_bn254::Fr;
use ark_ff::UniformRand;
use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use pcg_core::dpf::gen_dpf;
use pcg_core::pcg::Role;
use pcg_protocols::MockBitOt;
use rand::SeedableRng;
use spdz_pcg::{dpf_gen_oblivious, Prg2pcSession};
use std::sync::Arc;
use std::time::Instant;

fn make_delta() -> Block {
    let mut b = [0u8; 16];
    b[0] = 0x01;
    for (i, x) in b.iter_mut().enumerate().skip(1) {
        *x = 0x9F ^ (i as u8);
    }
    Block::new(b)
}

fn bench_dpf_gen(log_n: u32) -> std::time::Duration {
    let alpha = 3u64 & ((1u64 << log_n) - 1);
    let seed = 0xB0B_u64;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let beta = Fr::rand(&mut rng);

    let (k0_ref, k1_ref) = gen_dpf::<Fr>(log_n, alpha, beta, seed);
    let root_0 = k0_ref.root_seed;
    let root_1 = k1_ref.root_seed;

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

    let t = Instant::now();
    let _ = h0.join().unwrap();
    let _ = h1.join().unwrap();
    t.elapsed()
}

#[test]
fn dpf_gen_oblivious_ferret_bench() {
    eprintln!("\nFull oblivious DPF gen (Ferret-backed, persistent Garbler):");
    eprintln!("  log_n         end-to-end   per-expand (amortized)");
    for log_n in [2u32, 4, 6, 8] {
        let total = bench_dpf_gen(log_n);
        let n_expands = (log_n * 2) as u128;
        let per_expand = total.as_micros() / n_expands;
        eprintln!(
            "  {:>5}   {:>12.2?}   {:>8} us",
            log_n, total, per_expand
        );
    }
}

/// Generate many DPFs on a SINGLE Prg2pcSession — this is the real
/// production scenario for PCG batches. One bootstrap amortizes across
/// all DPFs.
fn bench_batch_dpf_gen(log_n: u32, n_dpfs: usize) -> std::time::Duration {
    let seed = 0xB4_u64;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);

    // Prepare N sets of (α, β, roots).
    let mut inputs: Vec<(u64, Fr, [u8; 16], [u8; 16], Fr, Fr)> =
        Vec::with_capacity(n_dpfs);
    for i in 0..n_dpfs {
        let alpha = (i as u64) & ((1u64 << log_n) - 1);
        let beta = Fr::rand(&mut rng);
        let (k0_ref, k1_ref) = gen_dpf::<Fr>(log_n, alpha, beta, seed + i as u64);
        let beta_0 = Fr::rand(&mut rng);
        let beta_1 = beta - beta_0;
        inputs.push((alpha, beta, k0_ref.root_seed, k1_ref.root_seed, beta_0, beta_1));
    }

    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    let inputs_p0 = inputs.clone();
    let inputs_p1 = inputs.clone();

    let h0 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net0, delta).unwrap();
        let mut ot = ot0;
        let t = Instant::now();
        for (alpha, _beta, root_0, _root_1, beta_0, _beta_1) in &inputs_p0 {
            let _ = dpf_gen_oblivious::<Fr, _, _>(
                &mut prg, &mut ot, Role::P0, *alpha, *beta_0, *root_0, log_n,
            )
            .unwrap();
        }
        t.elapsed()
    });
    let h1 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net1, delta).unwrap();
        let mut ot = ot1;
        for (_alpha, _beta, _root_0, root_1, _beta_0, beta_1) in &inputs_p1 {
            let alpha_1 = 0u64;
            let _ = dpf_gen_oblivious::<Fr, _, _>(
                &mut prg, &mut ot, Role::P1, alpha_1, *beta_1, *root_1, log_n,
            )
            .unwrap();
        }
    });

    let t0 = h0.join().unwrap();
    h1.join().unwrap();
    t0
}

#[test]
fn dpf_gen_oblivious_batch_amortization() {
    eprintln!("\nBatch oblivious DPF gen — one Prg2pcSession amortizes bootstrap:");
    eprintln!("  log_n  n_dpfs        total    per-DPF (amortized)");
    for (log_n, n_dpfs) in [(4u32, 4), (4, 16), (4, 64), (6, 16), (8, 16)] {
        let total = bench_batch_dpf_gen(log_n, n_dpfs);
        let per_dpf = total.as_micros() / n_dpfs as u128;
        eprintln!(
            "  {:>5}  {:>6}   {:>10.2?}   {:>10} us",
            log_n, n_dpfs, total, per_dpf
        );
    }
}
