//! Oblivious 2-party DPF generation.
//!
//! Public API: [`dpf_gen_oblivious`] generates a `DpfKey<F>` per party in
//! the **SAME FORMAT** as `pcg_core::dpf::gen_dpf` (the trusted-dealer
//! reference), but via a 2-party protocol that **does not leak α** to
//! either party.
//!
//! This is the oblivious DPF gen: the PCG cross-term DPFs (where
//! α = (p_i + q_j) mod N is the secret position) can be generated with
//! neither party learning any party's secret sparse-poly position.
//!
//! ## Building blocks used
//!
//! - [`Prg2pcSession`]: 2PC PRG on XOR-shared seeds (2× AES-128 via
//!   garbled circuits, Davies-Meyer construction matching pcg-core).
//!   Provides the per-level tree expansion.
//! - [`pcg_protocols::sec_and`] / [`pcg_protocols::sec_and_block`]:
//!   XOR-shared AND primitives for correction-word computation and
//!   oblivious state advancement.
//! - `bit × field OT` (built on `BitOt`'s block channel): for leaf
//!   bit-wise XOR→additive share conversion. Gilboa-style.
//!
//! ## Protocol (per tree level)
//!
//!   1. Run `prg_session.expand` TWICE — once per party's sub-tree seed.
//!      Produces XOR-shares of `(s_0_L, s_0_R, s_1_L, s_1_R)` matching
//!      the trusted-dealer's per-party PRG outputs.
//!   2. Compute public correction words via:
//!      - `cw_tL`, `cw_tR`: public XOR of local contributions (safe —
//!        masked by PRG randomness).
//!      - `cw_seed`: `sec_and_block` on α_i share × (s_L⊕s_R) share for
//!        each sub-tree, then public XOR.
//!   3. Advance state to next level via:
//!      - Reuse `ax_share` from cw_seed computation for `s_KEEP_share`.
//!      - One `sec_and` per sub-tree for `t_KEEP_share`.
//!      - Local XOR for `ctrl_cur × cw_seed` term (ctrl shared, cw_seed
//!        public).
//!
//! ## Leaf (final_correction)
//!
//! At the leaf, each party holds XOR-shares of
//! `(s_0_leaf, s_1_leaf, t_0, t_1)`, plus additive-shares of β.
//! [`secure_leaf_correction`] computes the public `final_correction`:
//!
//!   1. Convert XOR-shared bits of each leaf seed to additive-shared
//!      field element `f_b = F_map(s_b_leaf)` via 128 bit×field OTs.
//!      This exploits the now-bit-linear `pcg_core::dpf::seed_to_field`.
//!   2. Compute additive-shared `D = f_0 - f_1 - β` locally.
//!   3. Reveal `D` publicly (safe — it's equivalent to the public
//!      `final_correction` up to a ±1 sign).
//!   4. Compute additive-shared `2·t_0·D` via one bit-OT (D is now
//!      public, so this is bit × public-field).
//!   5. Reveal `FC = D - 2·t_0·D` → public `final_correction`.
//!
//! ## Cost
//!
//! Per DPF at log_n:
//!   - `2·log_n` `Prg2pcSession::expand` calls (~5-10 ms each with
//!     warm session)
//!   - `4·log_n` `sec_and/sec_and_block` (~ms each with Ferret OT)
//!   - `2·128 + 1` bit×field OTs at the leaf (~sub-ms each with Ferret)
//!
//! At log_n=20 with Ferret-backed OT: ~200 ms/DPF (estimate).
//!
//! ## Non-leakage argument
//!
//! - Per-level reveals (`cw_tL`, `cw_tR`, `cw_seed`): each party's
//!   contribution to the reveal is masked by PRG outputs (pseudorandom
//!   from the peer's perspective), so α_i stays hidden.
//! - Leaf reveal of `D`: `D` is equivalent up to a ±1 sign to the
//!   public `final_correction` that ends up in the DPF key — so no
//!   additional information is leaked beyond what the final key already
//!   reveals.
//! - Leaf reveal of `FC`: by construction this is the public key field.
//!
//! No individual leaf seed, ctrl bit, or α share is ever revealed.

#![cfg(feature = "gc")]

use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use eyre::Result;
use mpc_net::Network;
use pcg_core::dpf::{CorrectionWord, DpfKey};
use pcg_core::pcg::Role;
use pcg_protocols::{sec_and, sec_and_block, BitOt};

use crate::prg_2pc::Prg2pcSession;

// ───────────────────────── helpers ───────────────────────── //

fn xor16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// XOR-shared bit × public block → XOR-share of product (local).
///
/// When one factor is public and the other is XOR-shared, each party can
/// compute its share of the product locally: `(XOR-share bit) · (public block)`
/// gives an XOR-share of `bit · block`.
fn bit_share_times_public_block(bit_share: bool, block: [u8; 16]) -> [u8; 16] {
    if bit_share {
        block
    } else {
        [0u8; 16]
    }
}

/// OT-send a pair of field elements via `BitOt`'s block channel.
fn send_field_ot<F: PrimeField, OT: BitOt>(ot: &mut OT, m_0: F, m_1: F) -> Result<()> {
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

/// OT-receive a field element via `BitOt`'s block channel.
fn recv_field_ot<F: PrimeField, OT: BitOt>(ot: &mut OT, choice: bool) -> Result<F> {
    let byte_size = (F::MODULUS_BIT_SIZE as usize + 7) / 8;
    let n_blocks = (byte_size + 15) / 16;
    let mut buf = Vec::with_capacity(n_blocks * 16);
    for _ in 0..n_blocks {
        buf.extend_from_slice(&ot.recv_block(choice)?);
    }
    buf.truncate(byte_size);
    Ok(F::deserialize_compressed(&buf[..])?)
}

/// Reveal an additive-shared field element, returning the public value.
fn reveal_additive_share<F: PrimeField, OT: BitOt>(ot: &mut OT, my_share: F) -> Result<F> {
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

/// Convert XOR-shared bit × public coefficient → additive-shared field.
///
/// 1 bit-OT with field messages. Role::P0 is the OT sender.
fn xor_bit_to_additive_field<F: PrimeField, OT: BitOt>(
    ot: &mut OT,
    role: Role,
    bit_share: bool,
    coeff: F,
    rng: &mut impl rand::RngCore,
) -> Result<F> {
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
) -> Result<F> {
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

// ──────────────────── per-level shared state ──────────────────── //

/// XOR-shared joint state at one tree level (per-party view).
///
/// Represents shares of the logical pair `(seed_0_α_path, seed_1_α_path,
/// ctrl_0_α_path, ctrl_1_α_path)` that a trusted-dealer would maintain
/// along the α-path.
#[derive(Debug, Clone, Copy)]
struct SharedState {
    s_0_share: [u8; 16],
    s_1_share: [u8; 16],
    t_0_share: bool,
    t_1_share: bool,
}

/// Output of one [`oblivious_level`] call.
#[derive(Debug, Clone)]
struct LevelOutput {
    /// The public correction word for this level.
    cw: CorrectionWord,
    /// XOR-shared state for the next level.
    next_state: SharedState,
}

/// 2-party oblivious level: compute public correction word and advance
/// XOR-shared state.
///
/// See module docs for the protocol.
fn oblivious_level<N, OT>(
    prg: &mut Prg2pcSession<N>,
    ot: &mut OT,
    role: Role,
    alpha_share: bool,
    state: SharedState,
) -> Result<LevelOutput>
where
    N: Network + Unpin + 'static,
    OT: BitOt,
{
    // --- Two 2PC PRG expansions: one per party's sub-tree ---
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

    // --- Correction words ---
    // cw_l = t_0_l ⊕ t_1_l ⊕ α_i ⊕ 1
    let my_cw_tl_contrib =
        t_0_l_share ^ t_1_l_share ^ alpha_share ^ matches!(role, Role::P0);
    ot.reveal_bit(my_cw_tl_contrib)?;
    let peer_cw_tl_contrib = ot.recv_revealed_bit()?;
    let cw_l = my_cw_tl_contrib ^ peer_cw_tl_contrib;

    // cw_r = t_0_r ⊕ t_1_r ⊕ α_i
    let my_cw_tr_contrib = t_0_r_share ^ t_1_r_share ^ alpha_share;
    ot.reveal_bit(my_cw_tr_contrib)?;
    let peer_cw_tr_contrib = ot.recv_revealed_bit()?;
    let cw_r = my_cw_tr_contrib ^ peer_cw_tr_contrib;

    // cw_seed = s_0_lose ⊕ s_1_lose; s_b_lose = s_b_R ⊕ α·(s_b_L⊕s_b_R).
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

    // --- State advancement ---
    // Reuse alpha_diff to get s_KEEP_share without an extra sec_and_block.
    let s_0_keep_share = xor16(s_0_l_share, alpha_diff_0_share);
    let s_1_keep_share = xor16(s_1_l_share, alpha_diff_1_share);

    let s_0_next_share = xor16(
        s_0_keep_share,
        bit_share_times_public_block(state.t_0_share, cw_seed),
    );
    let s_1_next_share = xor16(
        s_1_keep_share,
        bit_share_times_public_block(state.t_1_share, cw_seed),
    );

    // Ctrl advance.
    let t_0_l_new_share = t_0_l_share ^ (state.t_0_share & cw_l);
    let t_0_r_new_share = t_0_r_share ^ (state.t_0_share & cw_r);
    let t_1_l_new_share = t_1_l_share ^ (state.t_1_share & cw_l);
    let t_1_r_new_share = t_1_r_share ^ (state.t_1_share & cw_r);

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

// ──────────────────── secure leaf correction ──────────────────── //

/// Compute `final_correction` securely from XOR-shared leaf state.
///
/// See module docs § "Leaf" for the protocol.
fn secure_leaf_correction<F: PrimeField, OT: BitOt>(
    ot: &mut OT,
    role: Role,
    s_0_leaf_share: [u8; 16],
    s_1_leaf_share: [u8; 16],
    t_0_share: bool,
    _t_1_share: bool,
    my_beta_share: F,
) -> Result<F> {
    let mut rng = rand::thread_rng();

    // Step 1: additive-shared f_b = F_map(s_b_leaf).
    let f_0_share = xor_seed_to_additive_field::<F, OT>(ot, role, s_0_leaf_share, &mut rng)?;
    let f_1_share = xor_seed_to_additive_field::<F, OT>(ot, role, s_1_leaf_share, &mut rng)?;

    // Step 2: D = f_0 - f_1 - β, additively shared (local).
    let d_share = f_0_share - f_1_share - my_beta_share;

    // Step 3: Reveal D (safe — equivalent information to final_correction).
    let d = reveal_additive_share::<F, OT>(ot, d_share)?;

    // Step 4: Compute additive share of 2·t_0·D.
    // Use 1 bit-OT (D is public so this is bit × public-field).
    //   2·t_0·D = 2·(t_0_0 + t_0_1 - 2·t_0_0·t_0_1)·D
    //           = 2·t_0_0·D + 2·t_0_1·D - 4·t_0_0·t_0_1·D
    let cross_share = match role {
        Role::P0 => {
            let t_0_0_d = if t_0_share { d } else { F::zero() };
            let r = F::rand(&mut rng);
            let m0 = -r;
            let m1 = t_0_0_d.double().double() - r; // 4·t_0_0·D - r
            send_field_ot::<F, OT>(ot, m0, m1)?;
            r
        }
        Role::P1 => recv_field_ot::<F, OT>(ot, t_0_share)?,
    };
    let two_t0_d_share = {
        let two_t_share_d = if t_0_share { d.double() } else { F::zero() };
        two_t_share_d - cross_share
    };

    // Step 5: FC = D - 2·t_0·D, additively shared.
    let fc_share = match role {
        Role::P0 => d - two_t0_d_share,
        Role::P1 => -two_t0_d_share,
    };

    // Step 6: Reveal FC.
    reveal_additive_share::<F, OT>(ot, fc_share)
}

// ──────────────────── top-level public API ──────────────────── //

/// 2-party oblivious DPF generation.
///
/// Produces a `DpfKey<F>` per party, in the same format as
/// [`pcg_core::dpf::gen_dpf`]'s trusted-dealer output. Running
/// [`pcg_core::dpf::eval_all`] on each party's key and summing gives
/// the point function `f(α) = β, f(x) = 0` for x ≠ α.
///
/// **Security**: neither party learns α. The protocol reveals only:
/// - The correction words at each level (masked by PRG outputs —
///   pseudorandom from each party's view).
/// - The intermediate value `D = f_0 - f_1 - β` at the leaf (which is
///   equivalent up to sign to the public `final_correction`).
/// - The final `final_correction` (already part of the public DPF key).
///
/// # Inputs
///
/// - `prg_session`: a [`Prg2pcSession`] previously initialized with
///   matching delta on both parties.
/// - `ot`: a [`BitOt`] implementation shared between the two parties
///   (for sec_and, sec_and_block, and the leaf bit-OTs).
/// - `role`: this party's role (P0 or P1).
/// - `my_alpha_share`: this party's XOR-share of the log_n-bit α.
/// - `my_beta_share`: this party's additive share of β ∈ F.
/// - `my_root`: this party's chosen random 128-bit root seed. Must be
///   different from the peer's root (any random value works).
/// - `log_n`: the log of the domain size.
///
/// # Invariants
///
/// - `my_alpha_share` must be a valid log_n-bit integer (< `2^log_n`).
/// - `my_beta_share + peer.my_beta_share = β` (additive share).
/// - Both parties must call with matching `log_n`.
///
/// # Output
///
/// A `DpfKey<F>` suitable for `pcg_core::dpf::eval_all`.
pub fn dpf_gen_oblivious<F, N, OT>(
    prg_session: &mut Prg2pcSession<N>,
    ot: &mut OT,
    role: Role,
    my_alpha_share: u64,
    my_beta_share: F,
    my_root: [u8; 16],
    log_n: u32,
) -> Result<DpfKey<F>>
where
    F: PrimeField,
    N: Network + Unpin + 'static,
    OT: BitOt,
{
    eyre::ensure!(log_n <= 64, "log_n must fit in u64");
    eyre::ensure!(
        my_alpha_share < (1u64 << log_n) || log_n == 64,
        "α share exceeds 2^log_n"
    );

    // Initial XOR-shared joint state at level 0:
    //   seed_0_shared = (P0: root_0, P1: 0) → logical = root_0
    //   seed_1_shared = (P0: 0, P1: root_1) → logical = root_1
    //   t_0_shared   = (P0: false, P1: false) → logical = false
    //   t_1_shared   = (P0: false, P1: true)  → logical = true
    let mut state = match role {
        Role::P0 => SharedState {
            s_0_share: my_root,
            s_1_share: [0u8; 16],
            t_0_share: false,
            t_1_share: false,
        },
        Role::P1 => SharedState {
            s_0_share: [0u8; 16],
            s_1_share: my_root,
            t_0_share: false,
            t_1_share: true,
        },
    };

    // Oblivious gen loop, one level at a time.
    let mut corrections = Vec::with_capacity(log_n as usize);
    for i in 0..log_n {
        // α_i is the (i+1)-th MSB of α (MSB-first descent).
        let alpha_i_share = ((my_alpha_share >> (log_n - 1 - i)) & 1) == 1;
        let out = oblivious_level(prg_session, ot, role, alpha_i_share, state)?;
        corrections.push(out.cw);
        state = out.next_state;
    }

    // Secure leaf final_correction.
    let final_correction = secure_leaf_correction::<F, _>(
        ot,
        role,
        state.s_0_share,
        state.s_1_share,
        state.t_0_share,
        state.t_1_share,
        my_beta_share,
    )?;

    // Assemble the per-party key.
    let (root_seed, root_ctrl) = match role {
        Role::P0 => (my_root, false),
        Role::P1 => (my_root, true),
    };
    Ok(DpfKey {
        log_n,
        root_seed,
        root_ctrl,
        corrections,
        final_correction,
        party: match role {
            Role::P0 => 0,
            Role::P1 => 1,
        },
    })
}

// ─────────────── PCG-flavored conversion wrappers ─────────────── //

/// Oblivious DPF gen with **XOR-shared α + multiplicatively-shared β**.
///
/// This is the shape natural for PCG cross-term DPFs where β = v_i · w_j.
/// Internally:
///   1. Converts the multiplicative β shares → additive via
///      [`pcg_protocols::mul_to_add_share`] (Gilboa OLE).
///   2. Delegates to [`dpf_gen_oblivious`].
///
/// Mirrors the signature of `pcg_protocols::dpf_gen_xor_alpha_mult_beta`
/// (the leaky version); the only added parameter is `prg_session`.
pub fn dpf_gen_oblivious_mult_beta<F, N, OT>(
    prg_session: &mut Prg2pcSession<N>,
    ot: &mut OT,
    role: Role,
    my_alpha_share: u64,
    my_beta_mult: F,
    my_root: [u8; 16],
    log_n: u32,
) -> Result<DpfKey<F>>
where
    F: PrimeField,
    N: Network + Unpin + 'static,
    OT: BitOt,
{
    use pcg_protocols::mul_to_add_share;
    let my_beta_add = mul_to_add_share(ot, role, my_beta_mult)?;
    dpf_gen_oblivious(prg_session, ot, role, my_alpha_share, my_beta_add, my_root, log_n)
}

/// Oblivious DPF gen with **additively-shared α + multiplicatively-shared β**.
///
/// This is the shape for PCG cross-terms: `α = (p_i + q_j) mod N` (additive
/// in Z_N), `β = v_i · w_j` (multiplicative in F).
///
/// Internally converts additive α → XOR-shared bits via
/// [`pcg_protocols::a2b_convert`], then delegates to
/// [`dpf_gen_oblivious_mult_beta`].
///
/// Mirrors `pcg_protocols::dpf_gen_additive_alpha` (the leaky version).
pub fn dpf_gen_oblivious_additive_alpha<F, N, OT>(
    prg_session: &mut Prg2pcSession<N>,
    ot: &mut OT,
    role: Role,
    my_alpha_additive: u64,
    my_beta_mult: F,
    my_root: [u8; 16],
    log_n: u32,
) -> Result<DpfKey<F>>
where
    F: PrimeField,
    N: Network + Unpin + 'static,
    OT: BitOt,
{
    use pcg_protocols::a2b_convert;
    let alpha_bits_xor = a2b_convert(ot, role, my_alpha_additive, log_n)?;
    let mut alpha_xor_share: u64 = 0;
    for (i, bit) in alpha_bits_xor.iter().enumerate() {
        if *bit {
            alpha_xor_share |= 1 << i;
        }
    }
    dpf_gen_oblivious_mult_beta(
        prg_session,
        ot,
        role,
        alpha_xor_share,
        my_beta_mult,
        my_root,
        log_n,
    )
}
