//! End-to-end oblivious DPF gen over the **production OT stack**:
//! Chou-Orlandi (CO15) base OTs → KOS extension → Ferret silent OT.
//!
//! Closes the last production-readiness gap: the previous Ferret tests
//! used `ideal_rcot` as bootstrap (insecure shared-delta). This test
//! validates that the full Chou-Orlandi-bootstrapped path produces the
//! same correct output (point function at α with value β).
//!
//! ## Performance caveat
//!
//! The first `Prg2pcSession::expand` call now pays:
//!   - Chou-Orlandi base OTs (~ms-range, public-key)
//!   - KOS OT extension (~ms)
//!   - Ferret LPN bootstrap (~ms)
//!
//! Total first-call: still measured in a few hundred ms. Subsequent
//! expands sub-ms (warm Ferret state).
//!
//! ## What this validates
//!
//! - `Prg2pcSession::new_ferret_co` constructs the full
//!   Chou-Orlandi → KOS → Ferret → DerandCOT → Garbler stack.
//! - End-to-end `dpf_gen_oblivious` produces correct DPF keys.
//! - `eval_all` gives the point function f(α)=β, f(x)=0.

#![cfg(feature = "gc")]

use ark_bn254::Fr;
use ark_ff::UniformRand;
use mpc_net::local::LocalNetwork;
use pcg_core::dpf::{eval_all, gen_dpf};
use pcg_core::pcg::Role;
use pcg_protocols::MockBitOt;
use rand::SeedableRng;
use spdz_pcg::{dpf_gen_oblivious, Prg2pcSession};
use std::sync::Arc;

/// Bug found 2026-04-16: `new_ferret_co` was generating a random delta
/// with arbitrary LSB and passing it to `KosSender::new` raw, while
/// `Delta::new(self.delta)` in `expand` silently flipped LSB → 1 for
/// the Garbler. Result: COT's delta differed from Garbler's delta in
/// the LSB → wrong labels → MAC commitment failure.
///
/// Fix: `new_ferret_co` now sets `delta_bytes[0] |= 0x01` before
/// constructing the session.
#[test]
fn dpf_gen_oblivious_chou_orlandi_backed_log_n_2() {
    let log_n = 2u32;
    let alpha = 2u64;
    let seed = 0xCAFE_BABE;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let beta = Fr::rand(&mut rng);

    let (k0_ref, k1_ref) = gen_dpf::<Fr>(log_n, alpha, beta, seed);
    let root_0 = k0_ref.root_seed;
    let root_1 = k1_ref.root_seed;

    let alpha_0 = alpha;
    let alpha_1 = 0u64;
    let beta_0 = Fr::rand(&mut rng);
    let beta_1 = beta - beta_0;

    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    let h0 = std::thread::spawn(move || {
        // KEY DIFFERENCE: new_ferret_co (production stack) instead of
        // new_ferret (ideal_rcot bootstrap). No delta parameter — each
        // party generates its own internally.
        let mut prg = Prg2pcSession::new_ferret_co(net0).unwrap();
        let mut ot = ot0;
        dpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P0, alpha_0, beta_0, root_0, log_n,
        )
        .unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new_ferret_co(net1).unwrap();
        let mut ot = ot1;
        dpf_gen_oblivious::<Fr, _, _>(
            &mut prg, &mut ot, Role::P1, alpha_1, beta_1, root_1, log_n,
        )
        .unwrap()
    });
    let k0 = h0.join().unwrap();
    let k1 = h1.join().unwrap();

    // Semantic correctness: combined eval_all = point function.
    let v0 = eval_all(&k0);
    let v1 = eval_all(&k1);
    for (i, (a, b)) in v0.iter().zip(v1.iter()).enumerate() {
        let sum = *a + *b;
        if i == alpha as usize {
            assert_eq!(sum, beta, "α={alpha}: sum at α mismatch");
        } else {
            assert_eq!(sum, Fr::from(0u64), "α={alpha}: off-path {i} nonzero");
        }
    }
}
