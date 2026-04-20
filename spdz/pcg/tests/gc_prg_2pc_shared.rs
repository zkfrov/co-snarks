//! `prg_2pc_shared`: PRG with XOR-shared outputs.
//!
//! Extends `gc_prg_2pc.rs` — instead of decoding the PRG output (revealing it
//! to both parties), we mask it inside the circuit before decoding. The
//! garbler supplies a random mask; after decoding, each party's share
//! (garbler's mask, evaluator's decoded value) XORs to the real PRG output.
//!
//! This is the API shape oblivious DPF gen's DPF gen needs: each tree level keeps
//! seed state XOR-shared throughout.
//!
//! Circuit:
//!   seed_a, seed_b : shared inputs (one per party)
//!   key_L, key_R   : public constants (domain-separation)
//!   mask_L, mask_R : garbler-private random 128-bit blocks
//!
//!   seed_xor   = XOR_128(seed_a, seed_b)
//!   out_L      = AES128(key_L, seed_xor)
//!   out_R      = AES128(key_R, seed_xor)
//!   out_L_mask = XOR_128(out_L, mask_L)          ← garbler's share = mask_L
//!   out_R_mask = XOR_128(out_R, mask_R)          ← garbler's share = mask_R
//!   decode(out_L_mask), decode(out_R_mask)       ← evaluator's share = decoded
//!
//! Validation: garbler_share XOR evaluator_share == plaintext PRG output.

#![cfg(feature = "gc")]

use futures::executor::block_on;
use mpc_net::{local::LocalNetwork, Network};
use mpz_circuits::{circuits::xor as xor_circuit, AES128};
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_memory_core::{binary::U8, correlated::Delta, Array, MemoryExt, ViewExt};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::{Call, CallableExt, Execute};
use once_cell::sync::Lazy;
use rand::{RngCore, SeedableRng};
use spdz_core::ot::async_io::SyncToAsyncIo;
use std::sync::Arc;

const K_LEFT: [u8; 16] = [0x00; 16];
const K_RIGHT: [u8; 16] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

static XOR_128: Lazy<Arc<mpz_circuits::Circuit>> = Lazy::new(|| Arc::new(xor_circuit(128)));

fn aes_block(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    let key = GenericArray::from(key);
    let cipher = aes::Aes128::new(&key);
    let mut block = GenericArray::from(msg);
    cipher.encrypt_block(&mut block);
    block.into()
}

fn plaintext_prg(seed: [u8; 16]) -> ([u8; 16], [u8; 16]) {
    (aes_block(K_LEFT, seed), aes_block(K_RIGHT, seed))
}

fn xor16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[test]
fn prg_2pc_shared_outputs_reconstruct_to_plaintext() {
    // Shared delta for this POC (same simplification as previous tests).
    let mut delta_bytes = [0u8; 16];
    delta_bytes[0] = 0x01;
    for (i, b) in delta_bytes.iter_mut().enumerate().skip(1) {
        *b = 0x5C ^ (i as u8);
    }
    let delta_block = Block::new(delta_bytes);
    let delta = Delta::new(delta_block);

    // XOR-shared 128-bit seed.
    let seed_0: [u8; 16] = [0xDE; 16];
    let seed_1: [u8; 16] = [0xAD; 16];
    let seed_true = xor16(seed_0, seed_1);
    let (exp_l, exp_r) = plaintext_prg(seed_true);

    // Garbler's pre-chosen random masks (communicated outside the circuit —
    // the garbler uses these both as mask inputs to the circuit AND as its
    // own shares after the protocol).
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xFACE);
    let mut mask_l = [0u8; 16];
    rng.fill_bytes(&mut mask_l);
    let mut mask_r = [0u8; 16];
    rng.fill_bytes(&mut mask_r);

    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    assert_eq!(net0.id(), 0);
    assert_eq!(net1.id(), 1);

    let h0 = std::thread::spawn(move || {
        let io = SyncToAsyncIo::new(net0);
        let mut ctx = Context::new_single_threaded(io);
        let (cot_send, _unused) = ideal_cot(delta_block);
        let mut gb = Garbler::new(cot_send, [0u8; 16], delta);

        // Allocate inputs.
        let seed_a: Array<U8, 16> = gb.alloc().unwrap();
        let seed_b: Array<U8, 16> = gb.alloc().unwrap();
        let key_l: Array<U8, 16> = gb.alloc().unwrap();
        let key_r: Array<U8, 16> = gb.alloc().unwrap();
        let m_l: Array<U8, 16> = gb.alloc().unwrap();
        let m_r: Array<U8, 16> = gb.alloc().unwrap();

        gb.mark_private(seed_a).unwrap(); // P0 share
        gb.mark_blind(seed_b).unwrap(); //   P1 share
        gb.mark_public(key_l).unwrap();
        gb.mark_public(key_r).unwrap();
        gb.mark_private(m_l).unwrap(); //    garbler-only mask
        gb.mark_private(m_r).unwrap();

        // XOR shares → full seed; AES with two keys; XOR with masks.
        let seed_xor: Array<U8, 16> = gb
            .call(Call::builder(XOR_128.clone()).arg(seed_a).arg(seed_b).build().unwrap())
            .unwrap();
        let out_l: Array<U8, 16> = gb
            .call(Call::builder(AES128.clone()).arg(key_l).arg(seed_xor).build().unwrap())
            .unwrap();
        let out_r: Array<U8, 16> = gb
            .call(Call::builder(AES128.clone()).arg(key_r).arg(seed_xor).build().unwrap())
            .unwrap();
        let out_l_masked: Array<U8, 16> = gb
            .call(Call::builder(XOR_128.clone()).arg(out_l).arg(m_l).build().unwrap())
            .unwrap();
        let out_r_masked: Array<U8, 16> = gb
            .call(Call::builder(XOR_128.clone()).arg(out_r).arg(m_r).build().unwrap())
            .unwrap();

        // Decode the masked outputs (both parties learn them).
        let mut l_fut = gb.decode(out_l_masked).unwrap();
        let mut r_fut = gb.decode(out_r_masked).unwrap();

        // Assign/commit.
        gb.assign(seed_a, seed_0).unwrap();
        gb.assign(key_l, K_LEFT).unwrap();
        gb.assign(key_r, K_RIGHT).unwrap();
        gb.assign(m_l, mask_l).unwrap();
        gb.assign(m_r, mask_r).unwrap();
        gb.commit(seed_a).unwrap();
        gb.commit(seed_b).unwrap();
        gb.commit(key_l).unwrap();
        gb.commit(key_r).unwrap();
        gb.commit(m_l).unwrap();
        gb.commit(m_r).unwrap();

        block_on(gb.execute_all(&mut ctx)).unwrap();
        // Drain — garbler doesn't use the decoded values (its shares are
        // the masks themselves); just confirm decoding completed.
        let _ = l_fut.try_recv().unwrap().unwrap();
        let _ = r_fut.try_recv().unwrap().unwrap();

        // Garbler's shares = the masks it picked.
        (mask_l, mask_r)
    });

    let h1 = std::thread::spawn(move || {
        let io = SyncToAsyncIo::new(net1);
        let mut ctx = Context::new_single_threaded(io);
        let (_unused, cot_recv) = ideal_cot(delta_block);
        let mut ev = Evaluator::new(cot_recv);

        let seed_a: Array<U8, 16> = ev.alloc().unwrap();
        let seed_b: Array<U8, 16> = ev.alloc().unwrap();
        let key_l: Array<U8, 16> = ev.alloc().unwrap();
        let key_r: Array<U8, 16> = ev.alloc().unwrap();
        let m_l: Array<U8, 16> = ev.alloc().unwrap();
        let m_r: Array<U8, 16> = ev.alloc().unwrap();

        ev.mark_blind(seed_a).unwrap();
        ev.mark_private(seed_b).unwrap();
        ev.mark_public(key_l).unwrap();
        ev.mark_public(key_r).unwrap();
        ev.mark_blind(m_l).unwrap();
        ev.mark_blind(m_r).unwrap();

        let seed_xor: Array<U8, 16> = ev
            .call(Call::builder(XOR_128.clone()).arg(seed_a).arg(seed_b).build().unwrap())
            .unwrap();
        let out_l: Array<U8, 16> = ev
            .call(Call::builder(AES128.clone()).arg(key_l).arg(seed_xor).build().unwrap())
            .unwrap();
        let out_r: Array<U8, 16> = ev
            .call(Call::builder(AES128.clone()).arg(key_r).arg(seed_xor).build().unwrap())
            .unwrap();
        let out_l_masked: Array<U8, 16> = ev
            .call(Call::builder(XOR_128.clone()).arg(out_l).arg(m_l).build().unwrap())
            .unwrap();
        let out_r_masked: Array<U8, 16> = ev
            .call(Call::builder(XOR_128.clone()).arg(out_r).arg(m_r).build().unwrap())
            .unwrap();

        let mut l_fut = ev.decode(out_l_masked).unwrap();
        let mut r_fut = ev.decode(out_r_masked).unwrap();

        ev.assign(seed_b, seed_1).unwrap();
        ev.assign(key_l, K_LEFT).unwrap();
        ev.assign(key_r, K_RIGHT).unwrap();
        ev.commit(seed_a).unwrap();
        ev.commit(seed_b).unwrap();
        ev.commit(key_l).unwrap();
        ev.commit(key_r).unwrap();
        ev.commit(m_l).unwrap();
        ev.commit(m_r).unwrap();

        block_on(ev.execute_all(&mut ctx)).unwrap();
        // Evaluator's shares = the (masked) decoded outputs.
        (
            l_fut.try_recv().unwrap().unwrap(),
            r_fut.try_recv().unwrap().unwrap(),
        )
    });

    let (gb_share_l, gb_share_r) = h0.join().unwrap();
    let (ev_share_l, ev_share_r) = h1.join().unwrap();

    // Reconstruct and compare.
    let got_l = xor16(gb_share_l, ev_share_l);
    let got_r = xor16(gb_share_r, ev_share_r);
    assert_eq!(got_l, exp_l, "shared left output must reconstruct to plaintext PRG_L");
    assert_eq!(got_r, exp_r, "shared right output must reconstruct to plaintext PRG_R");

    // Sanity: garbler's shares are indeed the masks (not the plaintext).
    assert_ne!(gb_share_l, exp_l, "garbler share should NOT equal plaintext (it's the mask)");
    assert_ne!(ev_share_l, exp_l, "evaluator share should NOT equal plaintext (it's masked)");
}
