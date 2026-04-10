//! Test SPDZ 2-party collaborative proving of a recursion circuit.

use ark_bn254::Bn254;
use co_noir::Bn254G1;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::transcript::TranscriptHasher;
use co_noir_common::types::ZeroKnowledge;
use co_spdz_acvm::types::SpdzAcvmType;
use co_ultrahonk::prelude::UltraHonk;
use mpc_net::local::LocalNetwork;
use spdz_core::preprocessing::create_lazy_preprocessing;
use std::fs::File;
use std::sync::Arc;

const CRS_PATH_G1: &str = "../../co-noir/co-noir-common/src/crs/bn254_g1.dat";
const CRS_PATH_G2: &str = "../../co-noir/co-noir-common/src/crs/bn254_g2.dat";
const CIRCUIT_DIR: &str = "../../test_vectors/noir/recursion";

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(has_zk: ZeroKnowledge, mac_free: bool) {
    let circuit_file = format!("{CIRCUIT_DIR}/kat/recursion.json");
    let witness_file = format!("{CIRCUIT_DIR}/kat/recursion.gz");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let witness = co_noir::witness_from_reader(File::open(&witness_file).unwrap())
        .expect("failed to parse witness");

    // All witness values are public (no secret inputs for this test)
    let witness: Vec<SpdzAcvmType<ark_bn254::Fr>> =
        witness.into_iter().map(SpdzAcvmType::Public).collect();

    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let vk = co_noir::generate_vk::<Bn254>(
        &constraint_system,
        prover_crs.clone(),
        verifier_crs,
    )
    .unwrap();

    // Use lazy preprocessing — generates triples/bits on demand in small batches.
    // No upfront allocation, no "ran out" errors, minimal RAM.
    let pk_prep_0 = create_lazy_preprocessing::<ark_bn254::Fr>(42, 0);
    let pk_prep_1 = create_lazy_preprocessing::<ark_bn254::Fr>(42, 1);
    let (prove_prep_0, prove_prep_1) = if mac_free {
        // MAC-free preprocessing: zero MAC key, no MAC computation
        let p0 = spdz_core::preprocessing::create_lazy_preprocessing_mac_free::<ark_bn254::Fr>(43, 0);
        let p1 = spdz_core::preprocessing::create_lazy_preprocessing_mac_free::<ark_bn254::Fr>(43, 1);
        (p0, p1)
    } else {
        let p0 = create_lazy_preprocessing::<ark_bn254::Fr>(43, 0);
        let p1 = create_lazy_preprocessing::<ark_bn254::Fr>(43, 1);
        (p0, p1)
    };

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let witness_0 = witness.clone();
    let witness_1 = witness;
    let crs_0 = prover_crs.clone();
    let crs_1 = prover_crs;
    let vk_0 = vk.clone();
    let vk_1 = vk.clone();
    let cs_0 = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let cs_1 = co_noir::get_constraint_system_from_artifact(&program_artifact);

    let t0 = std::thread::spawn(move || {
        let t = std::time::Instant::now();
        let pk = co_spdz_noir::generate_proving_key_spdz(
            Box::new(pk_prep_0), &cs_0, witness_0, &net0, &crs_0,
        ).expect("P0: pk generation failed");
        eprintln!("P0: pk generation took {:.1}s", t.elapsed().as_secs_f64());

        let t = std::time::Instant::now();
        let result = if mac_free {
            co_spdz_noir::prove_spdz_mac_free::<_, H, _>(
                &net0, Box::new(prove_prep_0), pk, &crs_0, has_zk, &vk_0.inner_vk,
            ).expect("P0: proving failed")
        } else {
            co_spdz_noir::prove_spdz::<_, H, _>(
                &net0, Box::new(prove_prep_0), pk, &crs_0, has_zk, &vk_0.inner_vk,
            ).expect("P0: proving failed")
        };
        eprintln!("P0: proving took {:.1}s (mac_free={})", t.elapsed().as_secs_f64(), mac_free);
        result
    });

    let t1 = std::thread::spawn(move || {
        let pk = co_spdz_noir::generate_proving_key_spdz(
            Box::new(pk_prep_1), &cs_1, witness_1, &net1, &crs_1,
        ).expect("P1: pk generation failed");

        if mac_free {
            co_spdz_noir::prove_spdz_mac_free::<_, H, _>(
                &net1, Box::new(prove_prep_1), pk, &crs_1, has_zk, &vk_1.inner_vk,
            ).expect("P1: proving failed")
        } else {
            co_spdz_noir::prove_spdz::<_, H, _>(
                &net1, Box::new(prove_prep_1), pk, &crs_1, has_zk, &vk_1.inner_vk,
            ).expect("P1: proving failed")
        }
    });

    let (proof_0, pi_0) = t0.join().expect("P0 thread panicked");
    let (proof_1, pi_1) = t1.join().expect("P1 thread panicked");

    assert_eq!(proof_0, proof_1, "Both parties must produce identical proofs");
    assert_eq!(pi_0, pi_1, "Both parties must produce identical public inputs");

    let is_valid = UltraHonk::<_, H>::verify(proof_0, &pi_0, &vk, has_zk).unwrap();
    assert!(is_valid, "SPDZ collaborative recursion proof must verify");
}

#[test]
#[ignore = "Recursion circuit is very slow with SPDZ"]
fn test_spdz_recursion_poseidon2() {
    proof_test::<co_noir_common::transcript::Poseidon2Sponge>(ZeroKnowledge::No, false);
}

#[test]
#[ignore = "Recursion circuit is very slow with SPDZ"]
fn test_spdz_recursion_mac_free() {
    proof_test::<co_noir_common::transcript::Poseidon2Sponge>(ZeroKnowledge::No, true);
}
