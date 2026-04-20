//! POC for 2PC AES-128 via mpz-garble.
//!
//! This test validates the integration between:
//!   - Our `mpc_net::Network` (via `LocalNetwork`)
//!   - `spdz_core::ot::async_io::SyncToAsyncIo` (bridges sync Network → async IO)
//!   - `mpz_common::Context` (async MPC context)
//!   - `mpz_ot::ideal::cot::ideal_cot` (ideal COT over the wire)
//!   - `mpz_garble::protocol::semihonest::{Garbler, Evaluator}` (half-gates GC)
//!   - `mpz_circuits::AES128` (built-in AES-128 boolean circuit)
//!
//! P0 acts as the garbler, holding a private AES key. P1 acts as the evaluator,
//! holding a private AES message. Both parties run AES-128 in 2PC and both
//! obtain the same ciphertext (decoded on both sides).
//!
//! We compare the 2PC output to plaintext AES evaluation to confirm correctness.
//!
//! **Next step (future session)**: swap `ideal_cot` → Ferret RCOT +
//! `DerandCOTSender`/`Receiver` to get production-grade OT. Once that's
//! working, wire up per-DPF-level 2PC PRG calls.

#![cfg(feature = "gc")]

use futures::executor::block_on;
use mpc_net::{local::LocalNetwork, Network};
use mpz_circuits::AES128;
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
use spdz_core::ot::async_io::SyncToAsyncIo;
use std::sync::Arc;

/// Reference AES-128 on plaintext inputs (uses the `aes` crate via mpz-core's
/// dependency tree). Used to verify the 2PC output.
fn aes_plaintext(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::Aes128;
    let key = GenericArray::from(key);
    let cipher = Aes128::new(&key);
    let mut block = GenericArray::from(msg);
    cipher.encrypt_block(&mut block);
    block.into()
}

#[test]
fn gc_aes_poc_two_party_over_local_network() {
    // Hard-coded delta — shared across both parties since this POC uses
    // `ideal_cot` (not real base OT). In production this is established via
    // Chou-Orlandi / ML-KEM / Ferret bootstrap. Delta's LSB must be set (GC
    // convention for the pointer bit).
    let mut delta_bytes = [0u8; 16];
    delta_bytes[0] = 0x01;
    for (i, b) in delta_bytes.iter_mut().enumerate().skip(1) {
        *b = 0xA5 ^ (i as u8);
    }
    let delta_block = Block::new(delta_bytes);
    let delta = Delta::new(delta_block);

    let key_p0: [u8; 16] = [0x00; 16];
    let msg_p1: [u8; 16] = [0x2A; 16];
    let expected = aes_plaintext(key_p0, msg_p1);

    // Two-party local network.
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());

    // Sanity check that party ids are 0/1.
    assert_eq!(net0.id(), 0);
    assert_eq!(net1.id(), 1);

    // Spawn each party in its own thread. Each blocks on its own async future.
    let h0 = std::thread::spawn(move || {
        let io = SyncToAsyncIo::new(net0);
        let mut ctx = Context::new_single_threaded(io);
        // P0 = Garbler. Owns cot_send (COT sender).
        let (cot_send, _cot_recv_unused) = ideal_cot(delta_block);
        let mut gb = Garbler::new(cot_send, [0u8; 16], delta);

        // Allocate Array<U8, 16> for both key (private to us) and msg
        // (blind to us — P1 holds the private value).
        let key: Array<U8, 16> = gb.alloc().unwrap();
        let msg: Array<U8, 16> = gb.alloc().unwrap();
        gb.mark_private(key).unwrap();
        gb.mark_blind(msg).unwrap();

        let ciphertext: Array<U8, 16> = gb
            .call(Call::builder(AES128.clone()).arg(key).arg(msg).build().unwrap())
            .unwrap();
        let mut ct_fut = gb.decode(ciphertext).unwrap();

        gb.assign(key, key_p0).unwrap();
        gb.commit(key).unwrap();
        gb.commit(msg).unwrap();

        block_on(gb.execute_all(&mut ctx)).unwrap();
        ct_fut.try_recv().unwrap().unwrap()
    });

    let h1 = std::thread::spawn(move || {
        let io = SyncToAsyncIo::new(net1);
        let mut ctx = Context::new_single_threaded(io);
        // P1 = Evaluator. Owns cot_recv.
        // We pass the SAME delta here just so ideal_cot's consistency check
        // is satisfied; the receiver doesn't actually learn delta from this.
        let (_cot_send_unused, cot_recv) = ideal_cot(delta_block);
        let mut ev = Evaluator::new(cot_recv);

        let key: Array<U8, 16> = ev.alloc().unwrap();
        let msg: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_blind(key).unwrap();
        ev.mark_private(msg).unwrap();

        let ciphertext: Array<U8, 16> = ev
            .call(Call::builder(AES128.clone()).arg(key).arg(msg).build().unwrap())
            .unwrap();
        let mut ct_fut = ev.decode(ciphertext).unwrap();

        ev.assign(msg, msg_p1).unwrap();
        ev.commit(key).unwrap();
        ev.commit(msg).unwrap();

        block_on(ev.execute_all(&mut ctx)).unwrap();
        ct_fut.try_recv().unwrap().unwrap()
    });

    let got0 = h0.join().unwrap();
    let got1 = h1.join().unwrap();

    assert_eq!(got0, got1, "garbler and evaluator ciphertexts must match");
    assert_eq!(got0, expected, "2PC AES output must match plaintext AES");
}
