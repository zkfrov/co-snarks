//! oblivious DPF gen — 2PC AES-128 via mpz-garble on top of Ferret
//! silent OT.
//!
//! Upgrades the earlier `gc_aes_poc.rs` test (which used `ideal_cot`) to use
//! production-grade OT:
//!
//!   FerretSender   → DerandCOTSender  → Garbler
//!   FerretReceiver → DerandCOTReceiver → Evaluator
//!
//! The Ferret bootstrap itself still uses `ideal_rcot` for base COTs — that's
//! a placeholder acceptable for our mac-free setting (SNARK provides
//! soundness). Swapping to Chou-Orlandi / ML-KEM base OTs is orthogonal.
//!
//! **What this test validates end-to-end**:
//!   - Ferret's RCOT flush protocol works over our `SyncToAsyncIo` bridge
//!   - `DerandCOTSender/Receiver` correctly converts Ferret RCOT → COT for GC
//!   - Garbled circuit labels transmitted via the real OT path decode correctly
//!   - Output matches plaintext AES

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
use mpz_ot::{
    cot::{DerandCOTReceiver, DerandCOTSender},
    ferret::{Receiver as FerretReceiver, Sender as FerretSender},
    ideal::rcot::ideal_rcot,
};
use mpz_ot_core::ferret::FerretConfig;
use mpz_vm_core::{Call, CallableExt, Execute};
use rand::{RngCore, SeedableRng};
use spdz_core::ot::async_io::SyncToAsyncIo;
use std::sync::Arc;

/// Plaintext AES-128 reference (same as the `ideal_cot` POC).
fn aes_plaintext(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::Aes128;
    let key = GenericArray::from(key);
    let cipher = Aes128::new(&key);
    let mut block = GenericArray::from(msg);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Build a Ferret RCOT sender with the given delta.
///
/// Mirrors the pattern used in `spdz_core::ot::ferret::FerretSession::new` —
/// bootstrap from `ideal_rcot`, then build the real Ferret sender on top.
fn build_ferret_sender(
    delta: Block,
) -> FerretSender<mpz_ot::ideal::rcot::IdealRCOTSender> {
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let bootstrap_seed = {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        Block::new(b)
    };
    let (bootstrap_sender, _unused_recv) = ideal_rcot(bootstrap_seed, delta);
    let sender_seed = {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        Block::new(b)
    };
    FerretSender::new(FerretConfig::default(), sender_seed, bootstrap_sender)
}

/// Build a Ferret RCOT receiver paired with the given delta.
fn build_ferret_receiver(
    delta: Block,
) -> FerretReceiver<mpz_ot::ideal::rcot::IdealRCOTReceiver> {
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let bootstrap_seed = {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        Block::new(b)
    };
    let (_unused_send, bootstrap_receiver) = ideal_rcot(bootstrap_seed, delta);
    let receiver_seed = {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        Block::new(b)
    };
    FerretReceiver::new(FerretConfig::default(), receiver_seed, bootstrap_receiver)
}

#[test]
fn gc_aes_ferret_two_party_over_local_network() {
    // Delta must satisfy the GC "point-and-permute" convention: LSB set to 1.
    // With `ideal_rcot` bootstrap we share the same delta on both sides — in a
    // real protocol this is negotiated via base OT.
    let mut delta_bytes = [0u8; 16];
    delta_bytes[0] = 0x01; // LSB = 1
    for (i, b) in delta_bytes.iter_mut().enumerate().skip(1) {
        *b = 0xA5 ^ (i as u8);
    }
    let delta_block = Block::new(delta_bytes);
    let delta = Delta::new(delta_block);

    let key_p0: [u8; 16] = [0x11; 16];
    let msg_p1: [u8; 16] = [0x22; 16];
    let expected = aes_plaintext(key_p0, msg_p1);

    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    assert_eq!(net0.id(), 0);
    assert_eq!(net1.id(), 1);

    // P0 = Garbler (Ferret RCOT sender → DerandCOTSender).
    let h0 = std::thread::spawn(move || {
        let io = SyncToAsyncIo::new(net0);
        let mut ctx = Context::new_single_threaded(io);

        let ferret_s = build_ferret_sender(delta_block);
        let cot_send = DerandCOTSender::new(ferret_s);
        let mut gb = Garbler::new(cot_send, [0u8; 16], delta);

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

    // P1 = Evaluator (Ferret RCOT receiver → DerandCOTReceiver).
    let h1 = std::thread::spawn(move || {
        let io = SyncToAsyncIo::new(net1);
        let mut ctx = Context::new_single_threaded(io);

        let ferret_r = build_ferret_receiver(delta_block);
        let cot_recv = DerandCOTReceiver::new(ferret_r);
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
    assert_eq!(got0, expected, "2PC AES (Ferret-backed) must equal plaintext AES");
}
