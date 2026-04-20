//! End-to-end integration test: oblivious DMPF generation.
//!
//! Validates that [`spdz_pcg::dmpf_gen_oblivious`] produces a
//! `SumOfDpfsKey<F>` whose combined `eval_all` matches the cyclic
//! convolution of the two parties' sparse polynomials — same semantic
//! contract as `pcg_protocols::dmpf_gen_sum_of_dpfs` (the leaky version),
//! but without leaking α.
//!
//! Uses **Ferret-backed** `Prg2pcSession` to amortize the LPN bootstrap
//! across all t² DPFs in the DMPF. This is the real production flow.
//!
//! This closes the last integration gap for oblivious DPF gen — the oblivious
//! gen is now wired through the full PCG primitive stack:
//!   `dpf_gen_oblivious`
//!     → `dpf_gen_oblivious_mult_beta` (β multiplicative → additive)
//!     → `dpf_gen_oblivious_additive_alpha` (α additive → XOR-shared)
//!     → `dmpf_gen_oblivious` (t² loop, single session)

#![cfg(feature = "gc")]

use ark_bn254::Fr;
use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use pcg_core::pcg::Role;
use pcg_core::ring_lpn::sparse_cyclic_mul_dense;
use pcg_core::sparse::SparsePoly;
use pcg_protocols::MockBitOt;
use rand::SeedableRng;
use spdz_pcg::{dmpf_gen_oblivious, Prg2pcSession};
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
fn dmpf_oblivious_matches_cyclic_convolution_log_n_4_t_2() {
    let log_n = 4u32;
    let n = 1usize << log_n;
    let t = 2;

    // Generate two t-sparse polynomials (one per party).
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xB0B_B0B);
    let sp0 = SparsePoly::<Fr>::random(n, t, &mut rng);
    let sp1 = SparsePoly::<Fr>::random(n, t, &mut rng);

    // Expected: true cyclic convolution.
    let expected = sparse_cyclic_mul_dense::<Fr>(&sp0, &sp1);

    // Spin up the 2-party oblivious gen.
    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    let sp0_p0 = sp0.clone();
    let sp1_p0 = sp1.clone();
    let sp0_p1 = sp0.clone();
    let sp1_p1 = sp1.clone();

    let peer_len_p0 = sp1.entries.len();
    let peer_len_p1 = sp0.entries.len();

    let h0 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net0, delta).unwrap();
        let mut ot = ot0;
        dmpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P0, &sp0_p0, peer_len_p0, log_n,
        )
        .unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net1, delta).unwrap();
        let mut ot = ot1;
        dmpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P1, &sp1_p1, peer_len_p1, log_n,
        )
        .unwrap()
    });

    let _ = sp1_p0; // quiet unused warning
    let _ = sp0_p1;

    let k0 = h0.join().unwrap();
    let k1 = h1.join().unwrap();

    // Each party's SumOfDpfsKey evaluates to its share; XOR-sum
    // (additive in F) should equal the true cyclic convolution.
    let v0 = k0.eval_all();
    let v1 = k1.eval_all();
    assert_eq!(v0.len(), n);
    assert_eq!(v1.len(), n);
    for i in 0..n {
        assert_eq!(v0[i] + v1[i], expected[i], "mismatch at position {i}");
    }
}
