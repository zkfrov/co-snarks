//! End-to-end SPDZ preprocessing backed by **oblivious DPF gen PCG**.
//!
//! This is the final integration test of the entire oblivious DPF gen effort.
//! Verifies:
//!
//!   1. `PcgPreprocessing::new_ring_lpn_oblivious` constructs successfully
//!      on both parties (driving the full oblivious Ring-LPN PCG gen
//!      under the hood).
//!   2. `next_triple` pulls Beaver triples from the resulting buffer.
//!   3. The triples satisfy the Beaver relation `a · b = c` when the
//!      two parties' shares are combined.
//!   4. MAC keys and other preprocessing material remain consistent.
//!
//! At this point: the SPDZ backend has fully oblivious, Ferret-backed,
//! oblivious DPF gen-compliant preprocessing. No α leak anywhere in the pipeline.

#![cfg(feature = "gc")]

use ark_bn254::Fr;
use ark_ff::UniformRand;
use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use pcg_protocols::MockBitOt;
use spdz_core::preprocessing::SpdzPreprocessing;
use spdz_core::types::combine_field_element;
use spdz_pcg::{PcgPreprocessing, Prg2pcSession};
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
fn spdz_preprocessing_oblivious_pcg_triples_satisfy_beaver_relation() {
    // Tiny PCG params: log_n=4 (N=16), t=2 → 4 cross-terms × 4 DPFs = 16
    // oblivious DPF gens. Produces 16 OLEs → 8 Beaver triples per batch.
    let log_n = 4u32;
    let t = 2usize;
    let a_seed = 0xA11C0DE;
    let shared_seed = 0xC0DE_F00D;
    let private_seed_p0 = 0x1111_2222;
    let private_seed_p1 = 0x3333_4444;

    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    // Each party constructs its PcgPreprocessing in its own thread.
    // The constructor runs the oblivious gen, which requires lock-step
    // network communication.
    let h0 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net0, delta).unwrap();
        let mut ot = ot0;
        PcgPreprocessing::<Fr>::new_ring_lpn_oblivious::<_, _>(
            0,
            shared_seed,
            private_seed_p0,
            log_n,
            t,
            a_seed,
            &mut prg,
            &mut ot,
        )
        .unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net1, delta).unwrap();
        let mut ot = ot1;
        PcgPreprocessing::<Fr>::new_ring_lpn_oblivious::<_, _>(
            1,
            shared_seed,
            private_seed_p1,
            log_n,
            t,
            a_seed,
            &mut prg,
            &mut ot,
        )
        .unwrap()
    });

    let mut p0 = h0.join().unwrap();
    let mut p1 = h1.join().unwrap();

    // Pull all available triples (one PCG batch = N/2 triples = 8 here).
    // Verify each satisfies a·b = c when shares are combined.
    let n_triples = (1usize << log_n) / 2;
    for i in 0..n_triples {
        let (a0, b0, c0) = p0.next_triple().unwrap();
        let (a1, b1, c1) = p1.next_triple().unwrap();

        let a = combine_field_element(a0, a1);
        let b = combine_field_element(b0, b1);
        let c = combine_field_element(c0, c1);
        assert_eq!(
            a * b,
            c,
            "triple #{i} from oblivious PCG does NOT satisfy Beaver relation"
        );
    }

    // MAC key shares should still sum to the shared MAC key (unchanged
    // path — uses shared_seed).
    assert_eq!(
        p0.mac_key_share() + p1.mac_key_share(),
        // Both parties have the same mac_key value (insecure storage in
        // PcgPreprocessing for testing only; production stores only the
        // share).
        {
            // Re-derive what the MAC key would be from shared_seed.
            use ark_ff::PrimeField;
            use rand::SeedableRng;
            use rand_chacha::ChaCha20Rng;
            let mut seed_rng = ChaCha20Rng::seed_from_u64(shared_seed);
            let mac_key = Fr::rand(&mut seed_rng);
            let _mk0 = Fr::rand(&mut seed_rng);
            let _ = Fr::MODULUS_BIT_SIZE;
            mac_key
        }
    );
}

#[test]
fn spdz_preprocessing_oblivious_multi_batch() {
    // Pre-generate 3 batches in one shot. Verify all 3 batches' triples
    // satisfy the Beaver relation. Bootstrap is amortized across the 3.
    let log_n = 4u32;
    let t = 2usize;
    let n_batches = 3usize;
    let a_seed = 0xA11C0DE;
    let shared_seed = 0xC0DE_F00D;
    let private_seed_p0 = 0x1111_2222;
    let private_seed_p1 = 0x3333_4444;

    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    let h0 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net0, delta).unwrap();
        let mut ot = ot0;
        PcgPreprocessing::<Fr>::new_ring_lpn_oblivious_batched::<_, _>(
            0,
            shared_seed,
            private_seed_p0,
            log_n,
            t,
            a_seed,
            n_batches,
            &mut prg,
            &mut ot,
        )
        .unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret(net1, delta).unwrap();
        let mut ot = ot1;
        PcgPreprocessing::<Fr>::new_ring_lpn_oblivious_batched::<_, _>(
            1,
            shared_seed,
            private_seed_p1,
            log_n,
            t,
            a_seed,
            n_batches,
            &mut prg,
            &mut ot,
        )
        .unwrap()
    });
    let mut p0 = h0.join().unwrap();
    let mut p1 = h1.join().unwrap();

    // Each batch has N/2 triples (for log_n=4, that's 8). Pull all
    // n_batches × 8 = 24 triples, verify each.
    let triples_per_batch = (1usize << log_n) / 2;
    let total_triples = n_batches * triples_per_batch;
    for i in 0..total_triples {
        let (a0, b0, c0) = p0.next_triple().unwrap();
        let (a1, b1, c1) = p1.next_triple().unwrap();
        let a = combine_field_element(a0, a1);
        let b = combine_field_element(b0, b1);
        let c = combine_field_element(c0, c1);
        assert_eq!(
            a * b,
            c,
            "triple #{i} (batch {}) Beaver relation failed",
            i / triples_per_batch
        );
    }
}
