//! Benchmark dark chess visibility circuits with SPDZ 2-party proving.

use ark_bn254::Bn254;
use co_noir::Bn254G1;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::transcript::Poseidon2Sponge;
use co_noir_common::types::ZeroKnowledge;
use co_spdz_acvm::types::SpdzAcvmType;
use co_ultrahonk::prelude::UltraHonk;
use mpc_net::local::LocalNetwork;
use spdz_core::preprocessing::create_lazy_preprocessing_mac_free;
use std::fs::File;
use std::sync::Arc;

const CRS_G1: &str = "../../co-noir/co-noir-common/src/crs/bn254_g1.dat";
const CRS_G2: &str = "../../co-noir/co-noir-common/src/crs/bn254_g2.dat";
const BASE: &str = "../../../taceo-2pc-poc";

fn bench(name: &str, circuit_json: &str, witness_gz: &str) {
    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(circuit_json).unwrap())
            .expect("failed to parse");
    let witness = co_noir::witness_from_reader(File::open(witness_gz).unwrap())
        .expect("failed to parse witness");
    let witness: Vec<SpdzAcvmType<ark_bn254::Fr>> =
        witness.into_iter().map(SpdzAcvmType::Public).collect();

    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_G1, crs_size, ZeroKnowledge::No).unwrap());
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_G2).unwrap();
    let vk = co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs.clone(), verifier_crs)
        .unwrap();

    let pk_prep_0 = create_lazy_preprocessing_mac_free::<ark_bn254::Fr>(42, 0);
    let pk_prep_1 = create_lazy_preprocessing_mac_free::<ark_bn254::Fr>(42, 1);
    let prove_prep_0 = create_lazy_preprocessing_mac_free::<ark_bn254::Fr>(43, 0);
    let prove_prep_1 = create_lazy_preprocessing_mac_free::<ark_bn254::Fr>(43, 1);

    let mut nets = LocalNetwork::new_with_timeout(2, std::time::Duration::from_secs(300)).into_iter();
    let (net0, net1) = (nets.next().unwrap(), nets.next().unwrap());

    let w0 = witness.clone();
    let w1 = witness;
    let crs0 = prover_crs.clone();
    let crs1 = prover_crs;
    let vk0 = vk.clone();
    let vk1 = vk.clone();
    let cs0 = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let cs1 = co_noir::get_constraint_system_from_artifact(&program_artifact);

    let total = std::time::Instant::now();

    let t0 = std::thread::spawn(move || {
        let t = std::time::Instant::now();
        let pk = co_spdz_noir::generate_proving_key_spdz(
            Box::new(pk_prep_0), &cs0, w0, &net0, &crs0,
        ).unwrap();
        let pk_time = t.elapsed().as_secs_f64();

        let t = std::time::Instant::now();
        let result = co_spdz_noir::prove_spdz_mac_free::<_, Poseidon2Sponge, _>(
            &net0, Box::new(prove_prep_0), pk, &crs0, ZeroKnowledge::No, &vk0.inner_vk,
        ).unwrap();
        let prove_time = t.elapsed().as_secs_f64();
        (result, pk_time, prove_time)
    });

    let t1 = std::thread::spawn(move || {
        let pk = co_spdz_noir::generate_proving_key_spdz(
            Box::new(pk_prep_1), &cs1, w1, &net1, &crs1,
        ).unwrap();
        co_spdz_noir::prove_spdz_mac_free::<_, Poseidon2Sponge, _>(
            &net1, Box::new(prove_prep_1), pk, &crs1, ZeroKnowledge::No, &vk1.inner_vk,
        ).unwrap()
    });

    let ((proof, pi), pk_time, prove_time) = t0.join().unwrap();
    let _ = t1.join().unwrap();
    let total_time = total.elapsed().as_secs_f64();

    let valid = UltraHonk::<_, Poseidon2Sponge>::verify(proof, &pi, &vk, ZeroKnowledge::No).unwrap();

    eprintln!(
        "{name:25} | PK: {pk_time:5.1}s | Prove: {prove_time:5.1}s | Total: {total_time:5.1}s | Valid: {valid}"
    );
}

#[test]
#[ignore = "Benchmark"]
fn bench_dark_chess_only() {
    eprintln!("{:25} | {:>8} | {:>10} | {:>10} | {}", "Circuit", "PK gen", "Proving", "Total", "Valid");
    eprintln!("{}", "-".repeat(80));
    bench(
        "dark_chess (full game)",
        "../../../aztec-chess-fog-of-war/circuit/target/dark_chess.json",
        "../../../aztec-chess-fog-of-war/circuit/target/dark_chess.gz",
    );
}

#[test]
#[ignore = "Benchmark"]
fn bench_all_chess_circuits() {
    eprintln!("{:25} | {:>8} | {:>10} | {:>10} | {}", "Circuit", "PK gen", "Proving", "Total", "Valid");
    eprintln!("{}", "-".repeat(80));

    bench(
        "dark_chess (full game)",
        "../../../aztec-chess-fog-of-war/circuit/target/dark_chess.json",
        "../../../aztec-chess-fog-of-war/circuit/target/dark_chess.gz",
    );
    bench(
        "circuit (4x4, 2pc)",
        &format!("{BASE}/circuit/target/dark_chess_vis.json"),
        &format!("{BASE}/circuit/target/dark_chess_vis.gz"),
    );
    bench(
        "opt (8x8, 4pc)",
        &format!("{BASE}/circuit-opt/target/dark_chess_opt.json"),
        &format!("{BASE}/circuit-opt/target/dark_chess_opt.gz"),
    );
    bench(
        "opt-full (8x8, 16pc)",
        &format!("{BASE}/circuit-opt-full/target/dark_chess_opt_full.json"),
        &format!("{BASE}/circuit-opt-full/target/dark_chess_opt_full.gz"),
    );
    bench(
        "medium (8x8, 4pc)",
        &format!("{BASE}/circuit-medium/target/dark_chess_med.json"),
        &format!("{BASE}/circuit-medium/target/dark_chess_med.gz"),
    );
    bench(
        "full (8x8, 16pc)",
        &format!("{BASE}/circuit-full/target/dark_chess_full.json"),
        &format!("{BASE}/circuit-full/target/dark_chess_full.gz"),
    );
}
