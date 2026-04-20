//! End-to-end test: `FerretBitOt` driving the `pcg-protocols` primitives
//! over a local network.
//!
//! Validates that:
//!   1. Ferret RCOT → derandomized bit/block OT works correctly
//!   2. `sec_and`, `sec_and_block`, `a2b_convert`, `mul_to_add_share` all run
//!      end-to-end on top of real OT
//!   3. The 2-party PCG seed gen (`gen_seed_2party`) produces correct OLEs
//!      when backed by Ferret

#![cfg(feature = "ferret")]

use ark_bn254::Fr;
use ark_ff::{UniformRand, Zero};
use mpc_net::local::LocalNetwork;
use pcg_core::pcg::Role;
use pcg_protocols::{a2b_convert, mul_to_add_share, sec_and, sec_and_block, BitOt};
use rand::{Rng, SeedableRng};
use spdz_pcg::FerretBitOt;
use std::sync::Arc;

// Smaller pool size for tests — still big enough for one DPF gen but keeps the
// initial Ferret flush under a second.
const TEST_POOL: usize = 4096;

fn spawn_pair<F0, F1, R0, R1>(f0: F0, f1: F1) -> (R0, R1)
where
    F0: FnOnce(FerretBitOt<mpc_net::local::LocalNetwork>) -> R0 + Send + 'static,
    F1: FnOnce(FerretBitOt<mpc_net::local::LocalNetwork>) -> R1 + Send + 'static,
    R0: Send + 'static,
    R1: Send + 'static,
{
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());

    let h0 = std::thread::spawn(move || {
        let ot = FerretBitOt::with_pool_size(net0, TEST_POOL).expect("ferret init p0");
        f0(ot)
    });
    let h1 = std::thread::spawn(move || {
        let ot = FerretBitOt::with_pool_size(net1, TEST_POOL).expect("ferret init p1");
        f1(ot)
    });
    (h0.join().unwrap(), h1.join().unwrap())
}

#[test]
fn ferret_bit_ot_send_recv_bit() {
    // Straight round-trip on the lowest primitive.
    let (got0, got1) = spawn_pair(
        |mut ot| {
            // P0 sends 4 bit-OT pairs, then is receiver for 4.
            ot.send_bit(false, true).unwrap();
            ot.send_bit(true, false).unwrap();
            ot.send_bit(true, true).unwrap();
            ot.send_bit(false, false).unwrap();
            let r0 = ot.recv_bit(false).unwrap();
            let r1 = ot.recv_bit(true).unwrap();
            let r2 = ot.recv_bit(false).unwrap();
            let r3 = ot.recv_bit(true).unwrap();
            (r0, r1, r2, r3)
        },
        |mut ot| {
            // P1 is receiver for the first 4 with known choices.
            let c0 = ot.recv_bit(false).unwrap(); // expect m_0 of pair 0 = false
            let c1 = ot.recv_bit(true).unwrap(); // expect m_1 of pair 1 = false
            let c2 = ot.recv_bit(false).unwrap(); // expect m_0 of pair 2 = true
            let c3 = ot.recv_bit(true).unwrap(); // expect m_1 of pair 3 = false
            // Then P1 sends 4 pairs where P0 is receiver.
            ot.send_bit(true, false).unwrap();
            ot.send_bit(true, true).unwrap();
            ot.send_bit(false, true).unwrap();
            ot.send_bit(false, false).unwrap();
            (c0, c1, c2, c3)
        },
    );
    // P0's receiver outputs (got0): choices were (false, true, false, true).
    //   P1 sent: (true,false), (true,true), (false,true), (false,false)
    assert_eq!(got0, (true, true, false, false));
    // P1's receiver outputs (got1): choices were (false, true, false, true).
    //   P0 sent: (false,true), (true,false), (true,true), (false,false)
    assert_eq!(got1, (false, false, true, false));
}

#[test]
fn ferret_bit_ot_send_recv_block() {
    let mut rng = rand::thread_rng();
    let m0: [u8; 16] = rng.r#gen();
    let m1: [u8; 16] = rng.r#gen();

    let (_, got) = spawn_pair(
        move |mut ot| {
            ot.send_block(m0, m1).unwrap();
        },
        move |mut ot| ot.recv_block(true).unwrap(),
    );
    assert_eq!(got, m1);

    let (_, got) = spawn_pair(
        move |mut ot| {
            ot.send_block(m0, m1).unwrap();
        },
        move |mut ot| ot.recv_block(false).unwrap(),
    );
    assert_eq!(got, m0);
}

#[test]
fn ferret_bit_ot_sec_and() {
    // Random XOR-shared inputs — verify sec_and produces correct shares of AND.
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
    for _ in 0..4 {
        let x0: bool = rng.r#gen();
        let x1: bool = rng.r#gen();
        let y0: bool = rng.r#gen();
        let y1: bool = rng.r#gen();
        let x = x0 ^ x1;
        let y = y0 ^ y1;
        let (z0, z1) = spawn_pair(
            move |mut ot| sec_and(&mut ot, Role::P0, x0, y0).unwrap(),
            move |mut ot| sec_and(&mut ot, Role::P1, x1, y1).unwrap(),
        );
        assert_eq!(z0 ^ z1, x & y);
    }
}

#[test]
fn ferret_bit_ot_sec_and_block() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(2);
    let x0: bool = rng.r#gen();
    let x1: bool = rng.r#gen();
    let a0: [u8; 16] = rng.r#gen();
    let a1: [u8; 16] = rng.r#gen();
    let x = x0 ^ x1;
    let a = {
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = a0[i] ^ a1[i];
        }
        out
    };
    let expected = if x { a } else { [0u8; 16] };
    let (z0, z1) = spawn_pair(
        move |mut ot| sec_and_block(&mut ot, Role::P0, x0, a0).unwrap(),
        move |mut ot| sec_and_block(&mut ot, Role::P1, x1, a1).unwrap(),
    );
    let mut xor = [0u8; 16];
    for i in 0..16 {
        xor[i] = z0[i] ^ z1[i];
    }
    assert_eq!(xor, expected);
}

#[test]
fn ferret_bit_ot_a2b_convert() {
    let log_n = 8u32;
    let n = 1u64 << log_n;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(3);
    for _ in 0..4 {
        let alpha: u64 = rng.gen_range(0..n);
        let share0: u64 = rng.gen_range(0..n);
        let share1 = (alpha + n - share0) % n;
        let (bits0, bits1) = spawn_pair(
            move |mut ot| a2b_convert(&mut ot, Role::P0, share0, log_n).unwrap(),
            move |mut ot| a2b_convert(&mut ot, Role::P1, share1, log_n).unwrap(),
        );
        let mut got = 0u64;
        for (i, (b0, b1)) in bits0.iter().zip(bits1.iter()).enumerate() {
            if b0 ^ b1 {
                got |= 1 << i;
            }
        }
        assert_eq!(got, alpha);
    }
}

#[test]
fn ferret_bit_ot_mul_to_add_share_bn254() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(4);
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let expected = a * b;

    let (c0, c1) = spawn_pair(
        move |mut ot| mul_to_add_share::<Fr, _>(&mut ot, Role::P0, a).unwrap(),
        move |mut ot| mul_to_add_share::<Fr, _>(&mut ot, Role::P1, b).unwrap(),
    );
    assert_eq!(c0 + c1, expected);
}

#[test]
#[ignore = "end-to-end 2-party PCG over Ferret takes ~minutes at tiny params"]
fn ferret_bit_ot_pcg_seed_gen_tiny() {
    use pcg_core::{ring_lpn_pcg::RingLpnPcgParams, sparse::SparsePoly};
    use pcg_protocols::gen_seed_2party;

    let _ = Fr::zero(); // hint

    // Tiny: log_n=6, t=2 → 4 DMPFs × 4 DPFs = 16 DPF gens.
    let params = RingLpnPcgParams::<Fr>::new(6, 2, 0xA11C0DE);
    let mut rng0 = rand_chacha::ChaCha20Rng::seed_from_u64(100);
    let mut rng1 = rand_chacha::ChaCha20Rng::seed_from_u64(200);
    let n = params.n();
    let t = params.t;
    let s0 = SparsePoly::<Fr>::random(n, t, &mut rng0);
    let e0 = SparsePoly::<Fr>::random(n, t, &mut rng0);
    let s1 = SparsePoly::<Fr>::random(n, t, &mut rng1);
    let e1 = SparsePoly::<Fr>::random(n, t, &mut rng1);

    let params_c0 = params.clone();
    let params_c1 = params.clone();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());

    let h0 = std::thread::spawn(move || {
        let mut ot = FerretBitOt::with_pool_size(net0, 1 << 17).unwrap();
        gen_seed_2party::<Fr, _>(&mut ot, Role::P0, params_c0, s0, e0).unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let mut ot = FerretBitOt::with_pool_size(net1, 1 << 17).unwrap();
        gen_seed_2party::<Fr, _>(&mut ot, Role::P1, params_c1, s1, e1).unwrap()
    });
    let seed0 = h0.join().unwrap();
    let seed1 = h1.join().unwrap();

    let ole0 = seed0.expand_to_ole();
    let ole1 = seed1.expand_to_ole();
    assert_eq!(ole0.len(), n);
    for i in 0..n {
        let (x0, y0) = ole0[i];
        let (x1, y1) = ole1[i];
        assert_eq!(x0 * x1, y0 + y1, "OLE pos {i}");
    }
}
