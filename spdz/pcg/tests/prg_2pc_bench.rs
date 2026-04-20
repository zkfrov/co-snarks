//! Per-expand cost micro-benchmark for `Prg2pcSession`.
//!
//! Measures the cost of each `expand` call individually to verify the
//! persistent Garbler/Evaluator optimization is working as expected.
//! The first call pays the Ferret LPN bootstrap (~2s); subsequent calls
//! should be orders of magnitude faster.

#![cfg(feature = "gc")]

use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use spdz_pcg::Prg2pcSession;
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

#[test]
fn prg_2pc_ferret_per_expand_cost() {
    // Drive 10 expands on a persistent session, timing each.
    const N: usize = 10;
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let delta = make_delta();

    let seeds_0: Vec<[u8; 16]> = (0..N).map(|i| [i as u8; 16]).collect();
    let seeds_1: Vec<[u8; 16]> = (0..N).map(|i| [(i as u8) ^ 0xFF; 16]).collect();

    let s0c = seeds_0.clone();
    let s1c = seeds_1.clone();

    let h0 = std::thread::spawn(move || {
        let mut sess = Prg2pcSession::new_ferret(net0, delta).unwrap();
        let mut timings = Vec::with_capacity(N);
        for s in &s0c {
            let t = Instant::now();
            let _ = sess.expand(*s).unwrap();
            timings.push(t.elapsed());
        }
        timings
    });
    let h1 = std::thread::spawn(move || {
        let mut sess = Prg2pcSession::new_ferret(net1, delta).unwrap();
        let mut timings = Vec::with_capacity(N);
        for s in &s1c {
            let t = Instant::now();
            let _ = sess.expand(*s).unwrap();
            timings.push(t.elapsed());
        }
        timings
    });

    let t0 = h0.join().unwrap();
    let t1 = h1.join().unwrap();

    eprintln!("\nPrg2pcSession::expand Ferret-backed per-call timings:");
    eprintln!("  {:>4} {:>12} {:>12}", "call", "P0 (gb)", "P1 (ev)");
    for i in 0..N {
        eprintln!(
            "  {:>4} {:>12.2?} {:>12.2?}",
            i, t0[i], t1[i]
        );
    }

    // Sanity: first call should be noticeably slower (bootstrap), subsequent
    // calls should be much faster. Exact threshold depends on hardware.
    let first_slower = t0[0] > t0[N - 1] * 2;
    eprintln!("\n  First call {} than last (ratio: {:.1}x)",
        if first_slower { "SIGNIFICANTLY slower" } else { "similar" },
        t0[0].as_secs_f64() / t0[N - 1].as_secs_f64()
    );

    let avg_after_first_us: u128 =
        t0[1..].iter().map(|d| d.as_micros()).sum::<u128>() / (N - 1) as u128;
    eprintln!("  Avg after first: {} us / expand", avg_after_first_us);
}
