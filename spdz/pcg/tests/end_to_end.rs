//! End-to-end integration test: PcgPreprocessing driving a real SPDZ
//! multiplication over LocalNetwork.

use ark_bn254::Fr;
use ark_ff::{UniformRand, Zero};
use mpc_net::local::LocalNetwork;
use rand::SeedableRng;
use spdz_core::arithmetic::{mul, open};
use spdz_core::types::share_field_element;
use spdz_core::SpdzState;
use spdz_pcg::PcgPreprocessing;

#[test]
fn pcg_preprocessing_drives_spdz_mul() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
    let shared_seed: u64 = 123_456;

    let p0_prep = PcgPreprocessing::<Fr>::new_insecure(0, shared_seed, 12);
    let p1_prep = PcgPreprocessing::<Fr>::new_insecure(1, shared_seed, 12);

    // Values to multiply — shared additively (mac-free: mac_key = 0).
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let [a0, a1] = share_field_element(a, Fr::zero(), &mut rng);
    let [b0, b1] = share_field_element(b, Fr::zero(), &mut rng);

    let networks = LocalNetwork::new(2);
    let mut nets = networks.into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = std::thread::spawn(move || {
        let mut state = SpdzState::new_mac_free(0, Box::new(p0_prep));
        let c = mul(&a0, &b0, &net0, &mut state).unwrap();
        open(&c, &net0, None).unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let mut state = SpdzState::new_mac_free(1, Box::new(p1_prep));
        let c = mul(&a1, &b1, &net1, &mut state).unwrap();
        open(&c, &net1, None).unwrap()
    });

    let r0 = h0.join().unwrap();
    let r1 = h1.join().unwrap();

    assert_eq!(r0, a * b, "party 0 reconstructed value != a*b");
    assert_eq!(r1, a * b, "party 1 reconstructed value != a*b");
}

#[test]
fn pcg_preprocessing_drives_multiple_muls() {
    let shared_seed: u64 = 999_999;
    let p0_prep = PcgPreprocessing::<Fr>::new_insecure(0, shared_seed, 14);
    let p1_prep = PcgPreprocessing::<Fr>::new_insecure(1, shared_seed, 14);

    const N: usize = 50;
    // Use a single rng to produce the same shares deterministically.
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
    let values: Vec<(Fr, Fr)> = (0..N)
        .map(|_| (Fr::rand(&mut rng), Fr::rand(&mut rng)))
        .collect();
    let expected: Vec<Fr> = values.iter().map(|(a, b)| *a * *b).collect();

    let mut shares: Vec<([_; 2], [_; 2])> = Vec::with_capacity(N);
    for (a, b) in &values {
        let a_shares = share_field_element(*a, Fr::zero(), &mut rng);
        let b_shares = share_field_element(*b, Fr::zero(), &mut rng);
        shares.push((a_shares, b_shares));
    }

    let shares0: Vec<_> = shares.iter().map(|(a, b)| (a[0], b[0])).collect();
    let shares1: Vec<_> = shares.iter().map(|(a, b)| (a[1], b[1])).collect();

    let networks = LocalNetwork::new(2);
    let mut nets = networks.into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = std::thread::spawn(move || {
        let mut state = SpdzState::new_mac_free(0, Box::new(p0_prep));
        shares0
            .into_iter()
            .map(|(a, b)| {
                let c = mul(&a, &b, &net0, &mut state).unwrap();
                open(&c, &net0, None).unwrap()
            })
            .collect::<Vec<_>>()
    });
    let h1 = std::thread::spawn(move || {
        let mut state = SpdzState::new_mac_free(1, Box::new(p1_prep));
        shares1
            .into_iter()
            .map(|(a, b)| {
                let c = mul(&a, &b, &net1, &mut state).unwrap();
                open(&c, &net1, None).unwrap()
            })
            .collect::<Vec<_>>()
    });

    let r0 = h0.join().unwrap();
    let r1 = h1.join().unwrap();

    for i in 0..N {
        assert_eq!(r0[i], expected[i], "p0 mul {i}");
        assert_eq!(r1[i], expected[i], "p1 mul {i}");
    }
}
