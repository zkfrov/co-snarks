//! `prg_2pc`: the atomic primitive for oblivious DPF gen.
//!
//! Given a 128-bit seed that is XOR-shared between the two parties, this
//! primitive produces a length-doubled PRG output that is also XOR-shared.
//! The PRG is implemented as two parallel AES-128 invocations with
//! domain-separated public keys:
//!
//!   prg(seed) = ( AES(K_L, seed), AES(K_R, seed) )
//!
//! The first 128 bits are the "left-child" material (child seed + control
//! bit); the second 128 bits are the "right-child" material. This matches the
//! two-output GGM-style PRG used in DPF constructions (Boyle-Gilboa-Ishai).
//!
//! ## Circuit composition
//!
//! We chain three `Call`s inside one garbled-circuit protocol run:
//!
//!   1. XOR_128(seed_a, seed_b) → seed_xor  (Free-XOR; effectively cost-free)
//!   2. AES128(K_L, seed_xor) → out_L
//!   3. AES128(K_R, seed_xor) → out_R
//!
//! Both AES keys are `mark_public`'d and assigned to the same constants on
//! both parties, so they contribute no OT cost. The dominant cost is the two
//! AES circuits (~6400 AND gates × 2).
//!
//! ## What this validates
//!
//! - Custom circuits (`XOR_128`) plug into the same `Call` machinery as AES
//! - Output of one circuit can be fed as input to a later circuit
//! - Public inputs (`mark_public`) work alongside private/blind inputs
//! - 2PC output of `prg_2pc` matches the plaintext reference
//!
//! This closes step 2 of the oblivious DPF gen roadmap. Next is rewriting `dpf_gen`
//! to carry XOR-shared state and call `prg_2pc` at each tree level.

#![cfg(feature = "gc")]

use futures::executor::block_on;
use mpc_net::{local::LocalNetwork, Network};
use mpz_circuits::{circuits::xor as xor_circuit, AES128};
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_memory_core::{
    binary::U8,
    correlated::Delta,
    Array, MemoryExt, ViewExt,
};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::{Call, CallableExt, Execute};
use once_cell::sync::Lazy;
use spdz_core::ot::async_io::SyncToAsyncIo;
use std::sync::Arc;

/// Public domain-separation key for the LEFT child of the PRG tree.
const K_LEFT: [u8; 16] = [0x00; 16];
/// Public domain-separation key for the RIGHT child.
const K_RIGHT: [u8; 16] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// XOR-128 circuit lazily constructed once.
static XOR_128: Lazy<Arc<mpz_circuits::Circuit>> = Lazy::new(|| Arc::new(xor_circuit(128)));

/// Plaintext AES-128.
fn aes_block(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::Aes128;
    let key = GenericArray::from(key);
    let cipher = Aes128::new(&key);
    let mut block = GenericArray::from(msg);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Reference PRG: `(AES(K_L, seed), AES(K_R, seed))`.
fn plaintext_prg(seed: [u8; 16]) -> ([u8; 16], [u8; 16]) {
    (aes_block(K_LEFT, seed), aes_block(K_RIGHT, seed))
}

#[test]
fn prg_2pc_matches_plaintext() {
    // Shared delta for the ideal_cot POC (same simplification as gc_aes_poc).
    let mut delta_bytes = [0u8; 16];
    delta_bytes[0] = 0x01;
    for (i, b) in delta_bytes.iter_mut().enumerate().skip(1) {
        *b = 0xC3 ^ (i as u8);
    }
    let delta_block = Block::new(delta_bytes);
    let delta = Delta::new(delta_block);

    // XOR-shared seed.
    let seed_0: [u8; 16] = [0xAA; 16];
    let seed_1: [u8; 16] = [0x55; 16];
    let mut seed_true = [0u8; 16];
    for i in 0..16 {
        seed_true[i] = seed_0[i] ^ seed_1[i];
    }
    let (exp_l, exp_r) = plaintext_prg(seed_true);

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

        // Inputs: two 16-byte shares + two public 16-byte keys.
        let seed_a: Array<U8, 16> = gb.alloc().unwrap();
        let seed_b: Array<U8, 16> = gb.alloc().unwrap();
        let key_l: Array<U8, 16> = gb.alloc().unwrap();
        let key_r: Array<U8, 16> = gb.alloc().unwrap();
        gb.mark_private(seed_a).unwrap(); // P0's share
        gb.mark_blind(seed_b).unwrap(); //   P1's share
        gb.mark_public(key_l).unwrap();
        gb.mark_public(key_r).unwrap();

        // Chain: XOR → AES-left, XOR → AES-right.
        let seed_xor: Array<U8, 16> = gb
            .call(Call::builder(XOR_128.clone()).arg(seed_a).arg(seed_b).build().unwrap())
            .unwrap();
        let out_l: Array<U8, 16> = gb
            .call(Call::builder(AES128.clone()).arg(key_l).arg(seed_xor).build().unwrap())
            .unwrap();
        let out_r: Array<U8, 16> = gb
            .call(Call::builder(AES128.clone()).arg(key_r).arg(seed_xor).build().unwrap())
            .unwrap();

        let mut l_fut = gb.decode(out_l).unwrap();
        let mut r_fut = gb.decode(out_r).unwrap();

        gb.assign(seed_a, seed_0).unwrap();
        gb.assign(key_l, K_LEFT).unwrap();
        gb.assign(key_r, K_RIGHT).unwrap();
        gb.commit(seed_a).unwrap();
        gb.commit(seed_b).unwrap();
        gb.commit(key_l).unwrap();
        gb.commit(key_r).unwrap();

        block_on(gb.execute_all(&mut ctx)).unwrap();
        (l_fut.try_recv().unwrap().unwrap(), r_fut.try_recv().unwrap().unwrap())
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
        ev.mark_blind(seed_a).unwrap(); //   P0's share (blind to us)
        ev.mark_private(seed_b).unwrap(); // P1's share
        ev.mark_public(key_l).unwrap();
        ev.mark_public(key_r).unwrap();

        let seed_xor: Array<U8, 16> = ev
            .call(Call::builder(XOR_128.clone()).arg(seed_a).arg(seed_b).build().unwrap())
            .unwrap();
        let out_l: Array<U8, 16> = ev
            .call(Call::builder(AES128.clone()).arg(key_l).arg(seed_xor).build().unwrap())
            .unwrap();
        let out_r: Array<U8, 16> = ev
            .call(Call::builder(AES128.clone()).arg(key_r).arg(seed_xor).build().unwrap())
            .unwrap();

        let mut l_fut = ev.decode(out_l).unwrap();
        let mut r_fut = ev.decode(out_r).unwrap();

        ev.assign(seed_b, seed_1).unwrap();
        ev.assign(key_l, K_LEFT).unwrap();
        ev.assign(key_r, K_RIGHT).unwrap();
        ev.commit(seed_a).unwrap();
        ev.commit(seed_b).unwrap();
        ev.commit(key_l).unwrap();
        ev.commit(key_r).unwrap();

        block_on(ev.execute_all(&mut ctx)).unwrap();
        (l_fut.try_recv().unwrap().unwrap(), r_fut.try_recv().unwrap().unwrap())
    });

    let (got_l_0, got_r_0) = h0.join().unwrap();
    let (got_l_1, got_r_1) = h1.join().unwrap();

    // `decode` broadcasts the cleartext to both parties, so both observe
    // the same value — and that value must match the plaintext PRG.
    assert_eq!(got_l_0, got_l_1, "garbler / evaluator disagree on left output");
    assert_eq!(got_r_0, got_r_1, "garbler / evaluator disagree on right output");
    assert_eq!(got_l_0, exp_l, "left output doesn't match plaintext AES(K_L, seed)");
    assert_eq!(got_r_0, exp_r, "right output doesn't match plaintext AES(K_R, seed)");
}
