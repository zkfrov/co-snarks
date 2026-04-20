//! Ultimate integration test: **full oblivious Ring-LPN PCG** produces
//! valid OLE correlations.
//!
//! End-to-end:
//!   1. Each party picks its own sparse `s` and `e` polynomials.
//!   2. `gen_seed_2party_oblivious` runs 4 oblivious DMPF gens for the
//!      4 cross-terms (s·s, s·e, e·s, e·e). One `Prg2pcSession` amortizes
//!      the Ferret LPN bootstrap across ALL t² × 4 DPFs.
//!   3. Each party calls `Seed2PartyOblivious::expand_to_ole` locally →
//!      length-N vector of OLE correlations.
//!   4. Verify the OLE invariant: `a_0 · a_1 = b_0 + b_1` at every
//!      position (where each party's (a_b, b_b) = (x_b, y_b) for that
//!      position).
//!
//! This is EXACTLY the same test as
//! `pcg_protocols::ring_lpn_pcg_2party::tests::two_party_pcg_ole_tiny`
//! (the leaky version), but using the oblivious gen.

#![cfg(feature = "gc")]

use ark_bn254::Fr;
use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use pcg_core::pcg::Role;
use pcg_core::ring_lpn_pcg::RingLpnPcgParams;
use pcg_core::sparse::SparsePoly;
use pcg_protocols::MockBitOt;
use rand::SeedableRng;
use spdz_pcg::{gen_seed_2party_oblivious, Prg2pcSession};
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
fn pcg_oblivious_produces_valid_ole_tiny() {
    // Same size as the leaky ring_lpn_pcg_2party::tests::two_party_pcg_ole_tiny.
    // log_n=4 (N=16), t=2 → 4 cross-terms × 4 DPFs each = 16 DPF gens total.
    let params = RingLpnPcgParams::<Fr>::new(4, 2, 0xA11C0DE);

    let mut rng0 = rand_chacha::ChaCha20Rng::seed_from_u64(100);
    let mut rng1 = rand_chacha::ChaCha20Rng::seed_from_u64(200);
    let n = params.n();
    let t = params.t;
    let s0 = SparsePoly::<Fr>::random(n, t, &mut rng0);
    let e0 = SparsePoly::<Fr>::random(n, t, &mut rng0);
    let s1 = SparsePoly::<Fr>::random(n, t, &mut rng1);
    let e1 = SparsePoly::<Fr>::random(n, t, &mut rng1);

    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    let params_c0 = params.clone();
    let params_c1 = params.clone();

    let h0 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net0, delta).unwrap();
        let mut ot = ot0;
        gen_seed_2party_oblivious::<Fr, _, _>(&mut prg, &mut ot, Role::P0, params_c0, s0, e0)
            .unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net1, delta).unwrap();
        let mut ot = ot1;
        gen_seed_2party_oblivious::<Fr, _, _>(&mut prg, &mut ot, Role::P1, params_c1, s1, e1)
            .unwrap()
    });
    let seed0 = h0.join().unwrap();
    let seed1 = h1.join().unwrap();

    let ole0 = seed0.expand_to_ole();
    let ole1 = seed1.expand_to_ole();
    assert_eq!(ole0.len(), n);
    assert_eq!(ole1.len(), n);

    // OLE invariant: at each position, x_0 · x_1 = y_0 + y_1.
    for i in 0..n {
        let (x0, y0) = ole0[i];
        let (x1, y1) = ole1[i];
        assert_eq!(x0 * x1, y0 + y1, "OLE invariant violated at position {i}");
    }
}
