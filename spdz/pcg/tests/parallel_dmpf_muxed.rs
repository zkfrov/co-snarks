//! Parallel oblivious 4-cross-term DMPF generation **over a single
//! underlying connection** via [`MuxNetwork`].
//!
//! Same parallelism semantics as `parallel_dmpf_demo.rs` (4 threads,
//! one per cross-term), but instead of 4 independent `LocalNetwork`
//! channels, all 4 streams share **one** underlying `LocalNetwork`
//! channel. The application-level multiplexer tags messages with
//! stream IDs and routes incoming traffic to per-stream queues.
//!
//! This is the network architecture that maps cleanly to production
//! TCP/QUIC: each party has ONE socket to the other party; the four
//! cross-term DMPFs share that socket via the multiplexer.
//!
//! For native QUIC, `QuicNetwork::fork()` is a more efficient
//! alternative (uses native QUIC streams). The multiplexer here works
//! with ANY `Network` — including TCP, LocalNetwork (for tests), etc.

#![cfg(feature = "gc")]

use ark_bn254::Fr;
use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use pcg_core::pcg::Role;
use pcg_core::ring_lpn::sparse_cyclic_mul_dense;
use pcg_core::sparse::SparsePoly;
use pcg_protocols::MockBitOt;
use rand::SeedableRng;
use spdz_pcg::{dmpf_gen_oblivious, MuxNetwork, Prg2pcSession};
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
fn muxed_parallel_4_dmpfs_over_one_socket() {
    let log_n = 4u32;
    let t = 2usize;
    let n = 1usize << log_n;

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x_DEAD_BEEF);
    let sp_p0 = SparsePoly::<Fr>::random(n, t, &mut rng);
    let sp_p1 = SparsePoly::<Fr>::random(n, t, &mut rng);
    // Expected: cyclic conv of the two sparse polys.
    let expected = sparse_cyclic_mul_dense::<Fr>(&sp_p0, &sp_p1);

    // ONE underlying LocalNetwork channel between the two parties.
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0_underlying = Arc::new(it.next().unwrap());
    let net1_underlying = Arc::new(it.next().unwrap());

    // 4 independent BitOt pairs, one per cross-term. Each party gets
    // its own half of each pair.
    let (ot00, ot01) = MockBitOt::new_pair();
    let (ot10, ot11) = MockBitOt::new_pair();
    let (ot20, ot21) = MockBitOt::new_pair();
    let (ot30, ot31) = MockBitOt::new_pair();

    let delta = make_delta();
    let peer_len_p0 = sp_p1.entries.len();
    let peer_len_p1 = sp_p0.entries.len();

    let sp_p0_a = sp_p0.clone();
    let sp_p0_b = sp_p0.clone();
    let sp_p0_c = sp_p0.clone();
    let sp_p0_d = sp_p0;
    let sp_p1_a = sp_p1.clone();
    let sp_p1_b = sp_p1.clone();
    let sp_p1_c = sp_p1.clone();
    let sp_p1_d = sp_p1;

    let t_start = Instant::now();
    let (keys_p0, keys_p1) = std::thread::scope(|outer| {
        let net0 = net0_underlying.clone();
        let net1 = net1_underlying.clone();

        let h_p0 = outer.spawn(move || {
            // Build the multiplexer over P0's underlying network; get 4
            // logical channels.
            let mux = MuxNetwork::new(net0, 4);
            let mut it = mux.into_iter();
            let log0 = Arc::new(it.next().unwrap());
            let log1 = Arc::new(it.next().unwrap());
            let log2 = Arc::new(it.next().unwrap());
            let log3 = Arc::new(it.next().unwrap());

            std::thread::scope(|s| {
                let h0 = s.spawn(|| {
                    let mut prg = Prg2pcSession::new_ferret(log0, delta).unwrap();
                    let mut ot = ot00;
                    dmpf_gen_oblivious::<Fr, _, _>(
                        &mut prg, &mut ot, Role::P0, &sp_p0_a, peer_len_p0, log_n,
                    )
                    .unwrap()
                });
                let h1 = s.spawn(|| {
                    let mut prg = Prg2pcSession::new_ferret(log1, delta).unwrap();
                    let mut ot = ot10;
                    dmpf_gen_oblivious::<Fr, _, _>(
                        &mut prg, &mut ot, Role::P0, &sp_p0_b, peer_len_p0, log_n,
                    )
                    .unwrap()
                });
                let h2 = s.spawn(|| {
                    let mut prg = Prg2pcSession::new_ferret(log2, delta).unwrap();
                    let mut ot = ot20;
                    dmpf_gen_oblivious::<Fr, _, _>(
                        &mut prg, &mut ot, Role::P0, &sp_p0_c, peer_len_p0, log_n,
                    )
                    .unwrap()
                });
                let h3 = s.spawn(|| {
                    let mut prg = Prg2pcSession::new_ferret(log3, delta).unwrap();
                    let mut ot = ot30;
                    dmpf_gen_oblivious::<Fr, _, _>(
                        &mut prg, &mut ot, Role::P0, &sp_p0_d, peer_len_p0, log_n,
                    )
                    .unwrap()
                });
                (
                    h0.join().unwrap(),
                    h1.join().unwrap(),
                    h2.join().unwrap(),
                    h3.join().unwrap(),
                )
            })
        });

        let h_p1 = outer.spawn(move || {
            let mux = MuxNetwork::new(net1, 4);
            let mut it = mux.into_iter();
            let log0 = Arc::new(it.next().unwrap());
            let log1 = Arc::new(it.next().unwrap());
            let log2 = Arc::new(it.next().unwrap());
            let log3 = Arc::new(it.next().unwrap());

            std::thread::scope(|s| {
                let h0 = s.spawn(|| {
                    let mut prg = Prg2pcSession::new_ferret(log0, delta).unwrap();
                    let mut ot = ot01;
                    dmpf_gen_oblivious::<Fr, _, _>(
                        &mut prg, &mut ot, Role::P1, &sp_p1_a, peer_len_p1, log_n,
                    )
                    .unwrap()
                });
                let h1 = s.spawn(|| {
                    let mut prg = Prg2pcSession::new_ferret(log1, delta).unwrap();
                    let mut ot = ot11;
                    dmpf_gen_oblivious::<Fr, _, _>(
                        &mut prg, &mut ot, Role::P1, &sp_p1_b, peer_len_p1, log_n,
                    )
                    .unwrap()
                });
                let h2 = s.spawn(|| {
                    let mut prg = Prg2pcSession::new_ferret(log2, delta).unwrap();
                    let mut ot = ot21;
                    dmpf_gen_oblivious::<Fr, _, _>(
                        &mut prg, &mut ot, Role::P1, &sp_p1_c, peer_len_p1, log_n,
                    )
                    .unwrap()
                });
                let h3 = s.spawn(|| {
                    let mut prg = Prg2pcSession::new_ferret(log3, delta).unwrap();
                    let mut ot = ot31;
                    dmpf_gen_oblivious::<Fr, _, _>(
                        &mut prg, &mut ot, Role::P1, &sp_p1_d, peer_len_p1, log_n,
                    )
                    .unwrap()
                });
                (
                    h0.join().unwrap(),
                    h1.join().unwrap(),
                    h2.join().unwrap(),
                    h3.join().unwrap(),
                )
            })
        });

        (h_p0.join().unwrap(), h_p1.join().unwrap())
    });
    let elapsed = t_start.elapsed();

    eprintln!(
        "muxed-parallel 4 DMPFs (log_n={log_n}, t={t}, ONE socket): {elapsed:.2?}"
    );

    // All 4 cross-terms used the SAME (sp_p0, sp_p1) inputs. Verify
    // that one of them produces the correct cyclic convolution. (We
    // don't have to check all four; they're independent runs of the
    // same algorithm on the same inputs — same correctness invariant.)
    let (k0_a, _, _, _) = keys_p0;
    let (k1_a, _, _, _) = keys_p1;
    let v0 = k0_a.eval_all();
    let v1 = k1_a.eval_all();
    for i in 0..n {
        assert_eq!(v0[i] + v1[i], expected[i], "muxed parallel mismatch at {i}");
    }
}
