//! Multi-level oblivious DPF gen — state advancement test.
//!
//! Extends `dpf_level0_cw.rs` from log_n=1 to log_n≥2. The protocol:
//!
//!   State at level i (XOR-shared between P0 and P1):
//!     (s_0_cur_share, s_1_cur_share, t_0_cur_share, t_1_cur_share)
//!   where the logical value (XOR of shares) is what the trusted-dealer
//!   would track at level i on the α-path.
//!
//!   At level 0, the state is initialized with trivial shares:
//!     - s_0_share: (P0: root_0, P1: 0)
//!     - s_1_share: (P0: 0,      P1: root_1)
//!     - t_0_share: (P0: false,  P1: false)   — logical = false
//!     - t_1_share: (P0: false,  P1: true)    — logical = true
//!
//!   At each level, [`oblivious_level`] runs:
//!     1. Two `Prg2pcSession::expand` calls → XOR-shares of (s_0_L, s_0_R,
//!        s_1_L, s_1_R) and the ctrl-bit shares (LSBs).
//!     2. Correction-word computation via sec_and_block + public XOR.
//!     3. Oblivious state advance to level i+1 via sec_and (on ctrl) and
//!        local XOR with public cw values.
//!
//! The critical assertion: CWs at EACH level match the trusted-dealer's
//! CWs for the same (root_0, root_1, α).

#![cfg(feature = "gc")]

use mpc_net::local::LocalNetwork;
use mpz_core::Block;
use pcg_core::dpf::{gen_dpf, CorrectionWord};
use pcg_core::pcg::Role;
use pcg_protocols::{sec_and, sec_and_block, BitOt, MockBitOt};
use spdz_pcg::Prg2pcSession;
use std::sync::Arc;

use ark_bn254::Fr;

fn xor16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Multiply a public block by an XOR-shared bit — local op (no OT).
/// Each party's XOR-share of (bit · block) = bit_my_share · block.
fn bit_share_times_public_block(bit_share: bool, block: [u8; 16]) -> [u8; 16] {
    if bit_share {
        block
    } else {
        [0u8; 16]
    }
}

fn make_delta() -> Block {
    let mut b = [0u8; 16];
    b[0] = 0x01;
    for (i, x) in b.iter_mut().enumerate().skip(1) {
        *x = 0x9F ^ (i as u8);
    }
    Block::new(b)
}

/// One-level of XOR-shared state (per-party view).
#[derive(Debug, Clone, Copy)]
struct SharedState {
    s_0_share: [u8; 16],
    s_1_share: [u8; 16],
    t_0_share: bool,
    t_1_share: bool,
}

/// Output of one `oblivious_level` call.
#[derive(Debug, Clone)]
struct LevelOutput {
    cw: CorrectionWord, // public
    next_state: SharedState, // XOR-shared
}

/// 2-party oblivious level: given XOR-shared current state and XOR-shared
/// α_i, produce the public correction word and XOR-shared next-level state.
///
/// Runs:
///   1. Two `Prg2pcSession::expand` calls (one per party's sub-tree seed).
///   2. CW computation via public reveals + 2× sec_and_block.
///   3. State advancement via local XOR + 2× sec_and.
fn oblivious_level<N, OT>(
    prg: &mut Prg2pcSession<N>,
    ot: &mut OT,
    role: Role,
    alpha_share: bool,
    state: SharedState,
) -> eyre::Result<LevelOutput>
where
    N: mpc_net::Network + Unpin + 'static,
    OT: BitOt,
{
    // --- 2PC PRG expansions ---
    //
    // prg.expand(share_of_joint_seed) produces XOR-shares of PRG applied
    // to the XOR-combined seed. At level 0, share_of_joint_seed[b=0] =
    // (root_0, 0) and share_of_joint_seed[b=1] = (0, root_1), so the
    // logical inputs are root_0 and root_1 exactly (matching trusted-
    // dealer semantics). At later levels the shares are non-trivial.
    let prg_s_0 = prg.expand(state.s_0_share)?;
    let prg_s_1 = prg.expand(state.s_1_share)?;

    let s_0_l_share = prg_s_0.s_l;
    let s_0_r_share = prg_s_0.s_r;
    let s_1_l_share = prg_s_1.s_l;
    let s_1_r_share = prg_s_1.s_r;
    let t_0_l_share = prg_s_0.t_l();
    let t_0_r_share = prg_s_0.t_r();
    let t_1_l_share = prg_s_1.t_l();
    let t_1_r_share = prg_s_1.t_r();

    // --- CWs ---
    // cw_l = t_0_l ⊕ t_1_l ⊕ α ⊕ 1
    let my_cw_tl_contrib = t_0_l_share
        ^ t_1_l_share
        ^ alpha_share
        ^ matches!(role, Role::P0);
    ot.reveal_bit(my_cw_tl_contrib)?;
    let peer_cw_tl_contrib = ot.recv_revealed_bit()?;
    let cw_l = my_cw_tl_contrib ^ peer_cw_tl_contrib;

    // cw_r = t_0_r ⊕ t_1_r ⊕ α
    let my_cw_tr_contrib = t_0_r_share ^ t_1_r_share ^ alpha_share;
    ot.reveal_bit(my_cw_tr_contrib)?;
    let peer_cw_tr_contrib = ot.recv_revealed_bit()?;
    let cw_r = my_cw_tr_contrib ^ peer_cw_tr_contrib;

    // cw_seed = s_0_lose ⊕ s_1_lose, where s_b_lose = s_b_R ⊕ α·(s_b_L⊕s_b_R).
    let diff_0_share = xor16(s_0_l_share, s_0_r_share);
    let alpha_diff_0_share = sec_and_block(ot, role, alpha_share, diff_0_share)?;
    let s_0_lose_share = xor16(s_0_r_share, alpha_diff_0_share);

    let diff_1_share = xor16(s_1_l_share, s_1_r_share);
    let alpha_diff_1_share = sec_and_block(ot, role, alpha_share, diff_1_share)?;
    let s_1_lose_share = xor16(s_1_r_share, alpha_diff_1_share);

    let my_cw_seed_share = xor16(s_0_lose_share, s_1_lose_share);
    ot.reveal_block(my_cw_seed_share)?;
    let peer_cw_seed_share = ot.recv_revealed_block()?;
    let cw_seed = xor16(my_cw_seed_share, peer_cw_seed_share);

    // --- State advance ---
    //
    // We reuse `alpha_diff_b_share` to get `s_b_keep_share` without an
    // extra sec_and_block:
    //   s_b_keep = s_b_L ⊕ α·(s_b_L ⊕ s_b_R)
    //            = s_b_L ⊕ alpha_diff_b
    let s_0_keep_share = xor16(s_0_l_share, alpha_diff_0_share);
    let s_1_keep_share = xor16(s_1_l_share, alpha_diff_1_share);

    // seed_next_share = s_keep_share ⊕ (t_cur_share · cw_seed). The second
    // term is XOR-shared-bit × public-block, so each party computes it
    // locally.
    let s_0_next_share = xor16(
        s_0_keep_share,
        bit_share_times_public_block(state.t_0_share, cw_seed),
    );
    let s_1_next_share = xor16(
        s_1_keep_share,
        bit_share_times_public_block(state.t_1_share, cw_seed),
    );

    // Ctrl advance:
    //   t_b_l_new = t_b_l ⊕ (t_b_cur · cw_l)
    //   t_b_r_new = t_b_r ⊕ (t_b_cur · cw_r)
    //   t_b_next  = t_b_l_new ⊕ α·(t_b_l_new ⊕ t_b_r_new)
    //
    // (t_b_cur · cw_l/cw_r) is XOR-shared-bit × public-bit = bit_share AND
    // cw_bit, local per party.
    let t_0_l_new_share = t_0_l_share ^ (state.t_0_share & cw_l);
    let t_0_r_new_share = t_0_r_share ^ (state.t_0_share & cw_r);
    let t_1_l_new_share = t_1_l_share ^ (state.t_1_share & cw_l);
    let t_1_r_new_share = t_1_r_share ^ (state.t_1_share & cw_r);

    // t_next = t_l_new ⊕ α·(t_l_new ⊕ t_r_new). Need sec_and for the shared-
    // bit × shared-bit product.
    let diff_t_0_share = t_0_l_new_share ^ t_0_r_new_share;
    let alpha_diff_t_0_share = sec_and(ot, role, alpha_share, diff_t_0_share)?;
    let t_0_next_share = t_0_l_new_share ^ alpha_diff_t_0_share;

    let diff_t_1_share = t_1_l_new_share ^ t_1_r_new_share;
    let alpha_diff_t_1_share = sec_and(ot, role, alpha_share, diff_t_1_share)?;
    let t_1_next_share = t_1_l_new_share ^ alpha_diff_t_1_share;

    Ok(LevelOutput {
        cw: CorrectionWord {
            cw_seed,
            cw_l,
            cw_r,
        },
        next_state: SharedState {
            s_0_share: s_0_next_share,
            s_1_share: s_1_next_share,
            t_0_share: t_0_next_share,
            t_1_share: t_1_next_share,
        },
    })
}

/// Convenience: full `log_n`-level oblivious CW computation, with state
/// carried forward level-by-level. Returns vector of all CWs.
fn oblivious_gen_cws<N, OT>(
    prg: &mut Prg2pcSession<N>,
    ot: &mut OT,
    role: Role,
    my_alpha_share: u64,
    my_root_share_as_p0: [u8; 16],
    my_root_share_as_p1: [u8; 16],
    log_n: u32,
) -> eyre::Result<Vec<CorrectionWord>>
where
    N: mpc_net::Network + Unpin + 'static,
    OT: BitOt,
{
    // Level-0 initialization:
    //   s_0_share: P0 has root_0, P1 has 0
    //   s_1_share: P0 has 0,     P1 has root_1
    //   t_0_share: (P0:false, P1:false)  — logical false
    //   t_1_share: (P0:false, P1:true)   — logical true
    let mut state = match role {
        Role::P0 => SharedState {
            s_0_share: my_root_share_as_p0,
            s_1_share: [0u8; 16],
            t_0_share: false,
            t_1_share: false,
        },
        Role::P1 => SharedState {
            s_0_share: [0u8; 16],
            s_1_share: my_root_share_as_p1,
            t_0_share: false,
            t_1_share: true,
        },
    };

    let mut cws = Vec::with_capacity(log_n as usize);
    for i in 0..log_n {
        // α_i is the (i+1)-th MSB of α (MSB-first), shared between parties.
        let alpha_i_share = ((my_alpha_share >> (log_n - 1 - i)) & 1) == 1;
        let out = oblivious_level(prg, ot, role, alpha_i_share, state)?;
        cws.push(out.cw);
        state = out.next_state;
    }
    Ok(cws)
}

// ────────────────────────── tests ────────────────────────── //

fn run_2party_cws(
    log_n: u32,
    alpha: u64,
    rng_seed: u64,
) -> (Vec<CorrectionWord>, Vec<CorrectionWord>, Vec<CorrectionWord>) {
    // Reference: trusted-dealer gen_dpf.
    let (k0_ref, _k1_ref) = gen_dpf::<Fr>(log_n, alpha, Fr::from(1u64), rng_seed);
    let root_0 = k0_ref.root_seed;
    let (_k0_again, k1_ref_again) = gen_dpf::<Fr>(log_n, alpha, Fr::from(1u64), rng_seed);
    let root_1 = k1_ref_again.root_seed;
    let expected_cws = k0_ref.corrections.clone();

    // α share: α = α_0 ⊕ α_1. Pick α_1 = 0 so α_0 = α (valid XOR share).
    let alpha_0_share = alpha;
    let alpha_1_share = 0u64;

    let delta = make_delta();
    let nets = LocalNetwork::new(2);
    let mut it = nets.into_iter();
    let net0 = Arc::new(it.next().unwrap());
    let net1 = Arc::new(it.next().unwrap());
    let (ot0, ot1) = MockBitOt::new_pair();

    let root_0_c = root_0;
    let root_1_c = root_1;

    let h0 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new(net0, delta).unwrap();
        let mut ot = ot0;
        oblivious_gen_cws(
            &mut prg,
            &mut ot,
            Role::P0,
            alpha_0_share,
            root_0_c,
            [0u8; 16],
            log_n,
        )
        .unwrap()
    });
    let h1 = std::thread::spawn(move || {
        let mut prg = Prg2pcSession::new(net1, delta).unwrap();
        let mut ot = ot1;
        oblivious_gen_cws(
            &mut prg,
            &mut ot,
            Role::P1,
            alpha_1_share,
            [0u8; 16],
            root_1_c,
            log_n,
        )
        .unwrap()
    });

    let cws_0 = h0.join().unwrap();
    let cws_1 = h1.join().unwrap();
    (cws_0, cws_1, expected_cws)
}

fn assert_cws_match(cws_0: &[CorrectionWord], cws_1: &[CorrectionWord], expected: &[CorrectionWord]) {
    assert_eq!(cws_0.len(), expected.len());
    assert_eq!(cws_1.len(), expected.len());
    for (i, (got_0, got_1)) in cws_0.iter().zip(cws_1.iter()).enumerate() {
        assert_eq!(got_0.cw_seed, got_1.cw_seed, "lvl {i} cw_seed P0/P1");
        assert_eq!(got_0.cw_l, got_1.cw_l, "lvl {i} cw_l P0/P1");
        assert_eq!(got_0.cw_r, got_1.cw_r, "lvl {i} cw_r P0/P1");
        assert_eq!(got_0.cw_seed, expected[i].cw_seed, "lvl {i} cw_seed != dealer");
        assert_eq!(got_0.cw_l, expected[i].cw_l, "lvl {i} cw_l != dealer");
        assert_eq!(got_0.cw_r, expected[i].cw_r, "lvl {i} cw_r != dealer");
    }
}

#[test]
fn log_n_2_cws_match_trusted_dealer_all_alphas() {
    // Try every α in [0, 4) for log_n=2.
    for alpha in 0u64..4 {
        let (cws_0, cws_1, expected) = run_2party_cws(2, alpha, 0xB0B + alpha);
        assert_cws_match(&cws_0, &cws_1, &expected);
    }
}

#[test]
fn log_n_3_cws_match_trusted_dealer_random_alphas() {
    // Log_n=3 covers deeper advancement (2 levels of state evolution).
    for (seed, alpha) in [(0xFEED, 0), (0xC0DE, 3), (0xBEEF, 5), (0xCAFE, 7)] {
        let (cws_0, cws_1, expected) = run_2party_cws(3, alpha, seed);
        assert_cws_match(&cws_0, &cws_1, &expected);
    }
}

// ────────────────── End-to-end gen with leaky-leaf POC ────────────────── //

use pcg_core::dpf::{eval_all, seed_to_field, DpfKey};

/// Run a FULL oblivious gen returning a `DpfKey<F>` per party.
///
/// **SECURITY CAVEAT**: the leaf step currently REVEALS the leaf seeds,
/// ctrl bits, and α (via XOR-shared reveals). This leaks α to both
/// parties. A secure version would replace the leaf reveal with either:
///   - A 2PC hash on XOR-shared inputs + share conversion to field.
///   - Bit-wise XOR → additive share conversion (requires 128 field OTs
///     but avoids 2PC hashing).
///
/// The rest of the gen (correction words, state advancement) IS oblivious
/// and already validated against the trusted-dealer reference. This POC
/// demonstrates that the produced keys have the correct structure and
/// pass `eval_all` semantic checks.
fn oblivious_gen_full<F: ark_ff::PrimeField, N, OT>(
    prg: &mut Prg2pcSession<N>,
    ot: &mut OT,
    role: Role,
    my_alpha_share: u64,
    my_beta_share: F,
    my_root_share_as_p0: [u8; 16],
    my_root_share_as_p1: [u8; 16],
    log_n: u32,
) -> eyre::Result<DpfKey<F>>
where
    N: mpc_net::Network + Unpin + 'static,
    OT: BitOt,
{
    // === Level 0..log_n: oblivious CW + state advance ===
    let mut state = match role {
        Role::P0 => SharedState {
            s_0_share: my_root_share_as_p0,
            s_1_share: [0u8; 16],
            t_0_share: false,
            t_1_share: false,
        },
        Role::P1 => SharedState {
            s_0_share: [0u8; 16],
            s_1_share: my_root_share_as_p1,
            t_0_share: false,
            t_1_share: true,
        },
    };
    let mut cws = Vec::with_capacity(log_n as usize);
    for i in 0..log_n {
        let alpha_i_share = ((my_alpha_share >> (log_n - 1 - i)) & 1) == 1;
        let out = oblivious_level(prg, ot, role, alpha_i_share, state)?;
        cws.push(out.cw);
        state = out.next_state;
    }

    // === Leaf final_correction (LEAKY — see caveat) ===
    //
    // We reveal the leaf joint state and α, then compute final_correction
    // in the clear using pcg-core's formula.
    ot.reveal_block(state.s_0_share)?;
    let peer_s_0_share = ot.recv_revealed_block()?;
    let s_0_leaf = xor16(state.s_0_share, peer_s_0_share);

    ot.reveal_block(state.s_1_share)?;
    let peer_s_1_share = ot.recv_revealed_block()?;
    let s_1_leaf = xor16(state.s_1_share, peer_s_1_share);

    ot.reveal_bit(state.t_0_share)?;
    let peer_t_0_share = ot.recv_revealed_bit()?;
    let t_0_leaf = state.t_0_share ^ peer_t_0_share;

    ot.reveal_bit(state.t_1_share)?;
    let peer_t_1_share = ot.recv_revealed_bit()?;
    let t_1_leaf = state.t_1_share ^ peer_t_1_share;

    // Also reveal α for the tag (needed by seed_to_field — SHA3 is not
    // XOR-linear). This is the same leak as the seeds.
    let my_alpha_bits_packed = my_alpha_share;
    let mut peer_alpha_bits_packed: u64 = 0;
    // Reveal bit-by-bit (reusing BitOt's single-bit channel).
    for i in 0..log_n {
        let my_bit = ((my_alpha_bits_packed >> i) & 1) == 1;
        ot.reveal_bit(my_bit)?;
        let peer_bit = ot.recv_revealed_bit()?;
        if peer_bit {
            peer_alpha_bits_packed |= 1u64 << i;
        }
    }
    let alpha = my_alpha_bits_packed ^ peer_alpha_bits_packed;

    // Also reveal β via one public field exchange (each party reveals its
    // additive share). β is not per se secret in the PCG use case — but
    // in a fully secure version, we'd keep it shared through OLE.
    // For this POC, reveal and combine.
    let my_beta_bytes = {
        use ark_serialize::CanonicalSerialize;
        let mut buf = Vec::new();
        my_beta_share.serialize_compressed(&mut buf).unwrap();
        buf
    };
    // Send via reveal_block in 2 chunks (BN254 Fr is 32 bytes).
    for chunk in my_beta_bytes.chunks(16) {
        let mut b = [0u8; 16];
        b[..chunk.len()].copy_from_slice(chunk);
        ot.reveal_block(b)?;
    }
    let mut peer_beta_bytes = Vec::new();
    let n_blocks = (my_beta_bytes.len() + 15) / 16;
    for _ in 0..n_blocks {
        peer_beta_bytes.extend_from_slice(&ot.recv_revealed_block()?);
    }
    peer_beta_bytes.truncate(my_beta_bytes.len());
    let peer_beta: F = {
        use ark_serialize::CanonicalDeserialize;
        F::deserialize_compressed(&peer_beta_bytes[..]).unwrap()
    };
    let beta = my_beta_share + peer_beta;

    // === Compute final_correction in the clear (exactly as trusted-dealer) ===
    let f0 = seed_to_field::<F>(s_0_leaf, alpha);
    let f1 = seed_to_field::<F>(s_1_leaf, alpha);
    assert_ne!(t_0_leaf, t_1_leaf, "on-α-path ctrl bits must differ");
    let final_correction = if !t_0_leaf && t_1_leaf {
        f0 - f1 - beta
    } else {
        beta - f0 + f1
    };

    // === Assemble key ===
    let (root_seed, root_ctrl) = match role {
        Role::P0 => (my_root_share_as_p0, false),
        Role::P1 => (my_root_share_as_p1, true),
    };
    Ok(DpfKey {
        log_n,
        root_seed,
        root_ctrl,
        corrections: cws,
        final_correction,
        party: match role {
            Role::P0 => 0,
            Role::P1 => 1,
        },
    })
}

#[test]
fn oblivious_gen_produces_valid_dpf_log_n_2() {
    use ark_ff::UniformRand;

    for alpha in 0u64..4 {
        let log_n = 2u32;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64_safe(0xABCD + alpha);
        let beta = Fr::rand(&mut rng);

        // Use gen_dpf for SAME rng_seed to extract roots that pcg-core
        // picks, so our 2-party gen uses matching roots. (Just a convenience
        // for testing against trusted-dealer — our gen uses the supplied
        // roots, whatever they are.)
        let (k0_ref, k1_ref) = gen_dpf::<Fr>(log_n, alpha, beta, 0xABCD + alpha);
        let root_0 = k0_ref.root_seed;
        let root_1 = k1_ref.root_seed;

        // α shares: α = α_0 ⊕ α_1. Pick α_1=0 so α_0=α.
        let alpha_0 = alpha;
        let alpha_1 = 0u64;
        // β shares: additive.
        let beta_0 = Fr::rand(&mut rng);
        let beta_1 = beta - beta_0;

        let delta = make_delta();
        let nets = LocalNetwork::new(2);
        let mut it = nets.into_iter();
        let net0 = Arc::new(it.next().unwrap());
        let net1 = Arc::new(it.next().unwrap());
        let (ot0, ot1) = MockBitOt::new_pair();

        let h0 = std::thread::spawn(move || {
            let mut prg = Prg2pcSession::new(net0, delta).unwrap();
            let mut ot = ot0;
            oblivious_gen_full::<Fr, _, _>(
                &mut prg,
                &mut ot,
                Role::P0,
                alpha_0,
                beta_0,
                root_0,
                [0u8; 16],
                log_n,
            )
            .unwrap()
        });
        let h1 = std::thread::spawn(move || {
            let mut prg = Prg2pcSession::new(net1, delta).unwrap();
            let mut ot = ot1;
            oblivious_gen_full::<Fr, _, _>(
                &mut prg,
                &mut ot,
                Role::P1,
                alpha_1,
                beta_1,
                [0u8; 16],
                root_1,
                log_n,
            )
            .unwrap()
        });
        let k0 = h0.join().unwrap();
        let k1 = h1.join().unwrap();

        // Assertion 1: keys match trusted-dealer exactly.
        assert_eq!(k0.root_seed, k0_ref.root_seed, "α={alpha}: P0 root");
        assert_eq!(k1.root_seed, k1_ref.root_seed, "α={alpha}: P1 root");
        assert_eq!(k0.corrections.len(), k0_ref.corrections.len());
        for (i, (got, exp)) in k0.corrections.iter().zip(k0_ref.corrections.iter()).enumerate() {
            assert_eq!(got.cw_seed, exp.cw_seed, "α={alpha} lvl {i}");
            assert_eq!(got.cw_l, exp.cw_l, "α={alpha} lvl {i}");
            assert_eq!(got.cw_r, exp.cw_r, "α={alpha} lvl {i}");
        }
        assert_eq!(k0.final_correction, k0_ref.final_correction, "α={alpha} final_correction");
        assert_eq!(k1.final_correction, k1_ref.final_correction, "α={alpha} final_correction P1");

        // Assertion 2: eval_all produces point function at α with value β.
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
}

// rand_chacha doesn't expose seed_from_u64_safe as a real method; use our own trivial helper.
// Actually rand::SeedableRng gives seed_from_u64 which we already use. Let me fix.
trait SeedFromU64Safe: rand::SeedableRng {
    fn seed_from_u64_safe(s: u64) -> Self {
        Self::seed_from_u64(s)
    }
}
impl<R: rand::SeedableRng> SeedFromU64Safe for R {}

// ─────────────── Secure leaf correction (bit-wise conversion) ─────────────── //

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{RngCore, SeedableRng};

/// Helper: OT-send a pair of field elements (`m_0`, `m_1`) via BitOt's block
/// channel. Field elements are serialized and sent in 16-byte chunks.
fn send_field_ot<F: PrimeField, OT: BitOt>(ot: &mut OT, m_0: F, m_1: F) -> eyre::Result<()> {
    let mut b0 = Vec::new();
    let mut b1 = Vec::new();
    m_0.serialize_compressed(&mut b0)?;
    m_1.serialize_compressed(&mut b1)?;
    let n_blocks = (b0.len() + 15) / 16;
    for i in 0..n_blocks {
        let mut c0 = [0u8; 16];
        let mut c1 = [0u8; 16];
        let lo = i * 16;
        let hi0 = (lo + 16).min(b0.len());
        let hi1 = (lo + 16).min(b1.len());
        c0[..hi0 - lo].copy_from_slice(&b0[lo..hi0]);
        c1[..hi1 - lo].copy_from_slice(&b1[lo..hi1]);
        ot.send_block(c0, c1)?;
    }
    Ok(())
}

/// Helper: OT-receive a field element via BitOt's block channel.
fn recv_field_ot<F: PrimeField, OT: BitOt>(ot: &mut OT, choice: bool) -> eyre::Result<F> {
    let byte_size = (F::MODULUS_BIT_SIZE as usize + 7) / 8;
    let n_blocks = (byte_size + 15) / 16;
    let mut buf = Vec::with_capacity(n_blocks * 16);
    for _ in 0..n_blocks {
        buf.extend_from_slice(&ot.recv_block(choice)?);
    }
    buf.truncate(byte_size);
    Ok(F::deserialize_compressed(&buf[..])?)
}

/// Convert an XOR-shared bit `b` with public coefficient `coeff` to an
/// additive-shared field element `coeff · b`.
///
/// Given shares `(b_0, b_1)` with `b = b_0 XOR b_1 ∈ {0,1}`:
///   `coeff · b = coeff · (b_0 + b_1 - 2·b_0·b_1)` in F.
///
/// Protocol (1 bit-OT with field messages):
///   P0 picks random r. Sends (m_0 = -r, m_1 = 2·coeff·b_0 - r).
///   P1 selects on b_1, receives m = -r + 2·coeff·b_0·b_1.
///   P0 additive share: coeff·b_0 - r
///   P1 additive share: coeff·b_1 - m  (= coeff·b_1 + r - 2·coeff·b_0·b_1)
///   Sum = coeff·b  ✓
///
/// Role convention (role == P0 is sender):
fn xor_bit_to_additive_field<F: PrimeField, OT: BitOt>(
    ot: &mut OT,
    role: Role,
    bit_share: bool,
    coeff: F,
    rng: &mut impl rand::RngCore,
) -> eyre::Result<F> {
    let coeff_b = if bit_share { coeff } else { F::zero() };
    match role {
        Role::P0 => {
            let r = F::rand(rng);
            let m0 = -r;
            let m1 = coeff_b.double() - r; // 2·coeff·b_0 - r
            send_field_ot::<F, OT>(ot, m0, m1)?;
            Ok(coeff_b - r)
        }
        Role::P1 => {
            let m = recv_field_ot::<F, OT>(ot, bit_share)?;
            Ok(coeff_b - m)
        }
    }
}

/// Convert an XOR-shared 128-bit seed to an additive-shared field element
/// `F_map(seed) = Σ 2^i · bit_i`.
///
/// Cost: 128 bit-OTs with field messages.
fn xor_seed_to_additive_field<F: PrimeField, OT: BitOt>(
    ot: &mut OT,
    role: Role,
    seed_share: [u8; 16],
    rng: &mut impl rand::RngCore,
) -> eyre::Result<F> {
    let mut acc = F::zero();
    let mut pow = F::one();
    for byte in seed_share.iter() {
        for bit_idx in 0..8 {
            let bit = (byte >> bit_idx) & 1 == 1;
            acc += xor_bit_to_additive_field::<F, OT>(ot, role, bit, pow, rng)?;
            pow.double_in_place();
        }
    }
    Ok(acc)
}

/// Reveal an additive-shared field element, returning the public value.
fn reveal_additive_share<F: PrimeField, OT: BitOt>(
    ot: &mut OT,
    my_share: F,
) -> eyre::Result<F> {
    let mut buf = Vec::new();
    my_share.serialize_compressed(&mut buf)?;
    let byte_size = buf.len();
    let n_blocks = (byte_size + 15) / 16;
    for i in 0..n_blocks {
        let mut b = [0u8; 16];
        let lo = i * 16;
        let hi = (lo + 16).min(byte_size);
        b[..hi - lo].copy_from_slice(&buf[lo..hi]);
        ot.reveal_block(b)?;
    }
    let mut peer_buf = Vec::with_capacity(byte_size);
    for _ in 0..n_blocks {
        peer_buf.extend_from_slice(&ot.recv_revealed_block()?);
    }
    peer_buf.truncate(byte_size);
    let peer: F = F::deserialize_compressed(&peer_buf[..])?;
    Ok(my_share + peer)
}

/// Compute `final_correction` SECURELY from XOR-shared leaf state.
///
/// **Security**: does NOT leak the individual leaf seeds, ctrl bits, β
/// shares, or α. Reveals only the combined `D = f_0 - f_1 - β` (public,
/// equivalent to revealing `final_correction` which IS in the public key)
/// and the final `final_correction` itself.
///
/// Cost per DPF leaf:
///   - 128 bit-OTs per seed × 2 seeds = 256 bit-OTs with field messages
///     (for additive-shared f_b)
///   - 1 bit-OT with field messages for 2·t_0·D cross product
///   - 2 field reveals (D, final_correction)
///
/// At Ferret throughput (~μs per OT): sub-ms per DPF leaf.
fn secure_leaf_correction<F: PrimeField, OT: BitOt>(
    ot: &mut OT,
    role: Role,
    s_0_leaf_share: [u8; 16],
    s_1_leaf_share: [u8; 16],
    t_0_share: bool,
    t_1_share: bool,
    my_beta_share: F,
) -> eyre::Result<F> {
    let mut rng = rand::thread_rng();

    // Step 1: XOR-shared seeds → additive-shared field elements.
    let f_0_share = xor_seed_to_additive_field::<F, OT>(ot, role, s_0_leaf_share, &mut rng)?;
    let f_1_share = xor_seed_to_additive_field::<F, OT>(ot, role, s_1_leaf_share, &mut rng)?;

    // Step 2: D = f_0 - f_1 - β, additively shared (local).
    let d_share = f_0_share - f_1_share - my_beta_share;

    // Step 3: Reveal D. Safe to reveal — equivalent info to the public
    // `final_correction` that ends up in the DPF key.
    let d = reveal_additive_share::<F, OT>(ot, d_share)?;

    // Step 4: Compute additive-shared 2·t_0·D where D is now public and
    // t_0 is XOR-shared.
    //
    //   2·t_0·D = 2·(t_0_0 + t_0_1 - 2·t_0_0·t_0_1)·D
    //           = 2·t_0_0·D + 2·t_0_1·D - 4·t_0_0·t_0_1·D
    //
    // Via bit-OT (sender P0 with field 4·t_0_0·D, receiver P1 with bit
    // t_0_1): additive shares of 4·t_0_0·t_0_1·D.
    //
    // Then additive share of 2·t_0·D:
    //   P0's share = 2·t_0_0·D - (P0's share of 4·t_0_0·t_0_1·D)
    //   P1's share = 2·t_0_1·D - (P1's share of 4·t_0_0·t_0_1·D)
    //
    // Standard protocol: P0 picks r, sends (m_0, m_1) = (-r, 4·t_0_0·D - r);
    // P1 selects on t_0_1.
    let cross_share = match role {
        Role::P0 => {
            let t_0_0_d = if t_0_share { d } else { F::zero() };
            let r = F::rand(&mut rng);
            let m0 = -r;
            let m1 = t_0_0_d.double().double() - r; // 4·t_0_0·D - r
            send_field_ot::<F, OT>(ot, m0, m1)?;
            r
        }
        Role::P1 => {
            recv_field_ot::<F, OT>(ot, t_0_share)?
        }
    };
    // Additive share of 2·t_0·D:
    let two_t0_d_share = {
        let two_t_share_d = if t_0_share { d.double() } else { F::zero() };
        two_t_share_d - cross_share
    };

    // Step 5: Compute additive-shared FC = (1 - 2·t_0) · D = D - 2·t_0·D.
    // D is public; each party has D as "its share" (P0) or 0 (P1) — use
    // role-based split.
    let fc_share = match role {
        Role::P0 => d - two_t0_d_share,
        Role::P1 => -two_t0_d_share,
    };

    // Step 6: Reveal FC (the public final_correction).
    let fc = reveal_additive_share::<F, OT>(ot, fc_share)?;

    // Silence unused
    let _ = (t_1_share,); // t_1 not directly needed for this flow
    Ok(fc)
}

/// Fully secure version of `oblivious_gen_full` — no leaf leak.
fn oblivious_gen_full_secure<F: PrimeField, N, OT>(
    prg: &mut Prg2pcSession<N>,
    ot: &mut OT,
    role: Role,
    my_alpha_share: u64,
    my_beta_share: F,
    my_root_share_as_p0: [u8; 16],
    my_root_share_as_p1: [u8; 16],
    log_n: u32,
) -> eyre::Result<DpfKey<F>>
where
    N: mpc_net::Network + Unpin + 'static,
    OT: BitOt,
{
    let mut state = match role {
        Role::P0 => SharedState {
            s_0_share: my_root_share_as_p0,
            s_1_share: [0u8; 16],
            t_0_share: false,
            t_1_share: false,
        },
        Role::P1 => SharedState {
            s_0_share: [0u8; 16],
            s_1_share: my_root_share_as_p1,
            t_0_share: false,
            t_1_share: true,
        },
    };
    let mut cws = Vec::with_capacity(log_n as usize);
    for i in 0..log_n {
        let alpha_i_share = ((my_alpha_share >> (log_n - 1 - i)) & 1) == 1;
        let out = oblivious_level(prg, ot, role, alpha_i_share, state)?;
        cws.push(out.cw);
        state = out.next_state;
    }

    // Secure leaf correction — no seed / α / ctrl reveals.
    let final_correction = secure_leaf_correction::<F, _>(
        ot,
        role,
        state.s_0_share,
        state.s_1_share,
        state.t_0_share,
        state.t_1_share,
        my_beta_share,
    )?;

    let (root_seed, root_ctrl) = match role {
        Role::P0 => (my_root_share_as_p0, false),
        Role::P1 => (my_root_share_as_p1, true),
    };
    Ok(DpfKey {
        log_n,
        root_seed,
        root_ctrl,
        corrections: cws,
        final_correction,
        party: match role {
            Role::P0 => 0,
            Role::P1 => 1,
        },
    })
}

#[test]
fn secure_leaf_dpf_produces_valid_point_function_log_n_2() {
    use ark_ff::UniformRand;

    for alpha in 0u64..4 {
        let log_n = 2u32;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x5EC_0 + alpha);
        let beta = Fr::rand(&mut rng);
        let (k0_ref, k1_ref) = gen_dpf::<Fr>(log_n, alpha, beta, 0x5EC_0 + alpha);
        let root_0 = k0_ref.root_seed;
        let root_1 = k1_ref.root_seed;

        let alpha_0 = alpha;
        let alpha_1 = 0u64;
        let beta_0 = Fr::rand(&mut rng);
        let beta_1 = beta - beta_0;

        let delta = make_delta();
        let nets = LocalNetwork::new(2);
        let mut it = nets.into_iter();
        let net0 = Arc::new(it.next().unwrap());
        let net1 = Arc::new(it.next().unwrap());
        let (ot0, ot1) = MockBitOt::new_pair();

        let h0 = std::thread::spawn(move || {
            let mut prg = Prg2pcSession::new(net0, delta).unwrap();
            let mut ot = ot0;
            oblivious_gen_full_secure::<Fr, _, _>(
                &mut prg,
                &mut ot,
                Role::P0,
                alpha_0,
                beta_0,
                root_0,
                [0u8; 16],
                log_n,
            )
            .unwrap()
        });
        let h1 = std::thread::spawn(move || {
            let mut prg = Prg2pcSession::new(net1, delta).unwrap();
            let mut ot = ot1;
            oblivious_gen_full_secure::<Fr, _, _>(
                &mut prg,
                &mut ot,
                Role::P1,
                alpha_1,
                beta_1,
                [0u8; 16],
                root_1,
                log_n,
            )
            .unwrap()
        });
        let k0 = h0.join().unwrap();
        let k1 = h1.join().unwrap();

        // The secure version must produce keys that match trusted-dealer
        // byte-for-byte (since CWs are identical, final_correction derivation
        // is the same formula, and seed_to_field is now bit-linear).
        assert_eq!(k0.root_seed, k0_ref.root_seed, "α={alpha}: P0 root");
        assert_eq!(k1.root_seed, k1_ref.root_seed, "α={alpha}: P1 root");
        for (i, (got, exp)) in k0.corrections.iter().zip(k0_ref.corrections.iter()).enumerate() {
            assert_eq!(got.cw_seed, exp.cw_seed, "α={alpha} lvl {i}");
            assert_eq!(got.cw_l, exp.cw_l, "α={alpha} lvl {i}");
            assert_eq!(got.cw_r, exp.cw_r, "α={alpha} lvl {i}");
        }
        assert_eq!(k0.final_correction, k0_ref.final_correction, "α={alpha} FC");

        // eval_all gives point function.
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
}

#[test]
fn secure_leaf_dpf_produces_valid_point_function_log_n_3() {
    use ark_ff::UniformRand;

    for (seed, alpha) in [(0xAAA, 0), (0xBBB, 3), (0xCCC, 5), (0xDDD, 7)] {
        let log_n = 3u32;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let beta = Fr::rand(&mut rng);
        let (k0_ref, k1_ref) = gen_dpf::<Fr>(log_n, alpha, beta, seed);
        let root_0 = k0_ref.root_seed;
        let root_1 = k1_ref.root_seed;

        let alpha_0 = alpha;
        let alpha_1 = 0u64;
        let beta_0 = Fr::rand(&mut rng);
        let beta_1 = beta - beta_0;

        let delta = make_delta();
        let nets = LocalNetwork::new(2);
        let mut it = nets.into_iter();
        let net0 = Arc::new(it.next().unwrap());
        let net1 = Arc::new(it.next().unwrap());
        let (ot0, ot1) = MockBitOt::new_pair();

        let h0 = std::thread::spawn(move || {
            let mut prg = Prg2pcSession::new(net0, delta).unwrap();
            let mut ot = ot0;
            oblivious_gen_full_secure::<Fr, _, _>(
                &mut prg, &mut ot, Role::P0, alpha_0, beta_0, root_0, [0u8; 16], log_n,
            )
            .unwrap()
        });
        let h1 = std::thread::spawn(move || {
            let mut prg = Prg2pcSession::new(net1, delta).unwrap();
            let mut ot = ot1;
            oblivious_gen_full_secure::<Fr, _, _>(
                &mut prg, &mut ot, Role::P1, alpha_1, beta_1, [0u8; 16], root_1, log_n,
            )
            .unwrap()
        });
        let k0 = h0.join().unwrap();
        let k1 = h1.join().unwrap();

        assert_eq!(k0.final_correction, k0_ref.final_correction, "α={alpha} FC");
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
}
