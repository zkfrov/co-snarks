//! End-to-end test: PcgPreprocessing driven by a real Ferret OT protocol
//! over a local network (not a mock).
//!
//! This is the Phase 2a.1 milestone — no trusted dealer, real crypto for
//! the OLE-per-triple phase.

#![cfg(feature = "ferret")]

use ark_bn254::Fr;
use ark_ff::{UniformRand, Zero};
use mpc_net::local::LocalNetwork;
use rand::SeedableRng;
use spdz_core::arithmetic::{mul, open};
use spdz_core::types::share_field_element;
use spdz_core::SpdzState;
use spdz_pcg::{FerretOleProtocol, PcgPreprocessing};
use std::sync::Arc;

#[test]
fn pcg_with_real_ferret_ole() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(12345);
    let shared_seed: u64 = 42;
    // Different private seeds per party — peer does not know them.
    let p0_private: u64 = 0x1111_AAAA;
    let p1_private: u64 = 0x2222_BBBB;

    // Value to multiply.
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let [a0, a1] = share_field_element(a, Fr::zero(), &mut rng);
    let [b0, b1] = share_field_element(b, Fr::zero(), &mut rng);

    // Two-party local network.
    let networks = LocalNetwork::new(2);
    let mut nets = networks.into_iter();
    let net0 = Arc::new(nets.next().unwrap());
    let net1 = Arc::new(nets.next().unwrap());

    // Spin up each party in its own thread. Each builds:
    //   1. A FerretOleProtocol connected to its peer via the LocalNetwork
    //   2. A PcgPreprocessing wrapping that protocol
    //   3. Runs a single SPDZ multiplication
    let net0_clone = net0.clone();
    let net1_clone = net1.clone();

    let h0 = std::thread::spawn(move || {
        let proto = FerretOleProtocol::new(net0_clone).expect("ferret init p0");
        let prep = PcgPreprocessing::<Fr>::new_with_protocol(
            0,
            p0_private,
            shared_seed,
            8, // 2^8 = 256 OLEs per batch → 128 triples
            Box::new(proto),
        );
        let mut state = SpdzState::new_mac_free(0, Box::new(prep));
        let c = mul(&a0, &b0, &*net0, &mut state).unwrap();
        open(&c, &*net0, None).unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let proto = FerretOleProtocol::new(net1_clone).expect("ferret init p1");
        let prep = PcgPreprocessing::<Fr>::new_with_protocol(
            1,
            p1_private,
            shared_seed,
            8,
            Box::new(proto),
        );
        let mut state = SpdzState::new_mac_free(1, Box::new(prep));
        let c = mul(&a1, &b1, &*net1, &mut state).unwrap();
        open(&c, &*net1, None).unwrap()
    });

    let r0 = h0.join().expect("p0 panicked");
    let r1 = h1.join().expect("p1 panicked");
    assert_eq!(r0, a * b, "party 0 result mismatch");
    assert_eq!(r1, a * b, "party 1 result mismatch");
}
