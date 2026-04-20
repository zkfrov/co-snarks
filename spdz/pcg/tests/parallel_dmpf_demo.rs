//! Parallel oblivious PCG generation: 4 cross-term DMPFs run concurrently
//! on 4 separate `Prg2pcSession`s + 4 LocalNetwork channels.
//!
//! Demonstrates the parallelism win when generating a Ring-LPN PCG seed:
//! the 4 cross-terms (s·s, s·e, e·s, e·e) are independent and can run
//! simultaneously, with each thread paying its own ~113 ms Ferret
//! bootstrap. Wall-clock approaches max(per-cross-term time) instead of
//! sum(over 4 cross-terms).
//!
//! This test demonstrates the pattern for callers who want maximum
//! parallelism. A future commit can lift it into a public
//! `gen_seed_2party_oblivious_parallel` API.

#![cfg(feature = "gc")]

use ark_bn254::Fr;
use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use pcg_core::pcg::Role;
use pcg_core::ring_lpn::lpn_expand;
use pcg_core::ring_lpn::{cyclic_conv_dense, sparse_cyclic_mul_dense};
use pcg_core::ring_lpn_pcg::RingLpnPcgParams;
use pcg_core::sparse::SparsePoly;
use pcg_protocols::MockBitOt;
use rand::SeedableRng;
use spdz_pcg::{dmpf_gen_oblivious, Prg2pcSession};
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

/// Run all 4 cross-term DMPFs **sequentially** on one Prg2pcSession.
fn sequential_4_cross_terms(
    log_n: u32,
    t: usize,
    s0: SparsePoly<Fr>,
    e0: SparsePoly<Fr>,
    s1: SparsePoly<Fr>,
    e1: SparsePoly<Fr>,
) -> std::time::Duration {
    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    let h0 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net0, delta).unwrap();
        let mut ot = ot0;
        let _ = dmpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P0, &s0, t, log_n,
        );
        let _ = dmpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P0, &s0, t, log_n,
        );
        let _ = dmpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P0, &e0, t, log_n,
        );
        let _ = dmpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P0, &e0, t, log_n,
        );
    });
    let h1 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net1, delta).unwrap();
        let mut ot = ot1;
        let _ = dmpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P1, &s1, t, log_n,
        );
        let _ = dmpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P1, &e1, t, log_n,
        );
        let _ = dmpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P1, &s1, t, log_n,
        );
        let _ = dmpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P1, &e1, t, log_n,
        );
    });

    let t0 = Instant::now();
    h0.join().unwrap();
    h1.join().unwrap();
    t0.elapsed()
}

/// Run all 4 cross-term DMPFs **in parallel**: 4 independent
/// (Prg2pcSession, BitOt, LocalNetwork) tuples, each on its own thread
/// per party (so 8 threads total, 4 per party).
fn parallel_4_cross_terms(
    log_n: u32,
    t: usize,
    s0: SparsePoly<Fr>,
    e0: SparsePoly<Fr>,
    s1: SparsePoly<Fr>,
    e1: SparsePoly<Fr>,
) -> std::time::Duration {
    // 4 independent network channels, one per cross-term.
    let mut nets_ss = LocalNetwork::new(2).into_iter();
    let net_ss_0 = Arc::new(nets_ss.next().unwrap());
    let net_ss_1 = Arc::new(nets_ss.next().unwrap());

    let mut nets_se = LocalNetwork::new(2).into_iter();
    let net_se_0 = Arc::new(nets_se.next().unwrap());
    let net_se_1 = Arc::new(nets_se.next().unwrap());

    let mut nets_es = LocalNetwork::new(2).into_iter();
    let net_es_0 = Arc::new(nets_es.next().unwrap());
    let net_es_1 = Arc::new(nets_es.next().unwrap());

    let mut nets_ee = LocalNetwork::new(2).into_iter();
    let net_ee_0 = Arc::new(nets_ee.next().unwrap());
    let net_ee_1 = Arc::new(nets_ee.next().unwrap());

    let delta = make_delta();
    let (ot_ss_0, ot_ss_1) = MockBitOt::new_pair();
    let (ot_se_0, ot_se_1) = MockBitOt::new_pair();
    let (ot_es_0, ot_es_1) = MockBitOt::new_pair();
    let (ot_ee_0, ot_ee_1) = MockBitOt::new_pair();

    // Same per-cross-term input selection as gen_seed_2party_oblivious.
    let s0_ss = s0.clone();
    let s0_se = s0.clone();
    let e0_es = e0.clone();
    let e0_ee = e0.clone();
    let s1_ss = s1.clone();
    let e1_se = e1.clone();
    let s1_es = s1.clone();
    let e1_ee = e1.clone();

    let t_start = Instant::now();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut prg = Prg2pcSession::new_ferret(net_ss_0, delta).unwrap();
            let mut ot = ot_ss_0;
            let _ = dmpf_gen_oblivious::<Fr, _, _>(
                &mut prg, &mut ot, Role::P0, &s0_ss, t, log_n,
            );
        });
        scope.spawn(|| {
            let mut prg = Prg2pcSession::new_ferret(net_ss_1, delta).unwrap();
            let mut ot = ot_ss_1;
            let _ = dmpf_gen_oblivious::<Fr, _, _>(
                &mut prg, &mut ot, Role::P1, &s1_ss, t, log_n,
            );
        });
        scope.spawn(|| {
            let mut prg = Prg2pcSession::new_ferret(net_se_0, delta).unwrap();
            let mut ot = ot_se_0;
            let _ = dmpf_gen_oblivious::<Fr, _, _>(
                &mut prg, &mut ot, Role::P0, &s0_se, t, log_n,
            );
        });
        scope.spawn(|| {
            let mut prg = Prg2pcSession::new_ferret(net_se_1, delta).unwrap();
            let mut ot = ot_se_1;
            let _ = dmpf_gen_oblivious::<Fr, _, _>(
                &mut prg, &mut ot, Role::P1, &e1_se, t, log_n,
            );
        });
        scope.spawn(|| {
            let mut prg = Prg2pcSession::new_ferret(net_es_0, delta).unwrap();
            let mut ot = ot_es_0;
            let _ = dmpf_gen_oblivious::<Fr, _, _>(
                &mut prg, &mut ot, Role::P0, &e0_es, t, log_n,
            );
        });
        scope.spawn(|| {
            let mut prg = Prg2pcSession::new_ferret(net_es_1, delta).unwrap();
            let mut ot = ot_es_1;
            let _ = dmpf_gen_oblivious::<Fr, _, _>(
                &mut prg, &mut ot, Role::P1, &s1_es, t, log_n,
            );
        });
        scope.spawn(|| {
            let mut prg = Prg2pcSession::new_ferret(net_ee_0, delta).unwrap();
            let mut ot = ot_ee_0;
            let _ = dmpf_gen_oblivious::<Fr, _, _>(
                &mut prg, &mut ot, Role::P0, &e0_ee, t, log_n,
            );
        });
        scope.spawn(|| {
            let mut prg = Prg2pcSession::new_ferret(net_ee_1, delta).unwrap();
            let mut ot = ot_ee_1;
            let _ = dmpf_gen_oblivious::<Fr, _, _>(
                &mut prg, &mut ot, Role::P1, &e1_ee, t, log_n,
            );
        });
    });
    t_start.elapsed()
}

#[test]
fn parallel_vs_sequential_speedup() {
    eprintln!("\n4-cross-term DMPF gen — sequential vs 4-way parallel:");
    eprintln!("  config           sequential   parallel    speedup");
    for (log_n, t) in [(4u32, 2usize), (4, 4), (6, 4)] {
        let n = 1usize << log_n;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xBABE + log_n as u64 + t as u64);
        let s0 = SparsePoly::<Fr>::random(n, t, &mut rng);
        let e0 = SparsePoly::<Fr>::random(n, t, &mut rng);
        let s1 = SparsePoly::<Fr>::random(n, t, &mut rng);
        let e1 = SparsePoly::<Fr>::random(n, t, &mut rng);

        let seq = sequential_4_cross_terms(log_n, t, s0.clone(), e0.clone(), s1.clone(), e1.clone());
        let par = parallel_4_cross_terms(log_n, t, s0, e0, s1, e1);
        eprintln!(
            "  log_n={:>2} t={:>2}    {:>10.2?}   {:>10.2?}   {:.2}×",
            log_n,
            t,
            seq,
            par,
            seq.as_secs_f64() / par.as_secs_f64()
        );
    }
    let _ = (lpn_expand::<Fr>, cyclic_conv_dense::<Fr>, sparse_cyclic_mul_dense::<Fr>);
    let _ = RingLpnPcgParams::<Fr>::new;
}
