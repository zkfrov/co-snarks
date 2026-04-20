//! 2-party PRG via garbled circuits — the inner loop of oblivious DPF gen
//! oblivious DPF generation.
//!
//! Given a 128-bit seed that is XOR-shared between the two parties,
//! [`Prg2pcSession::expand`] produces XOR-shares of the PRG output. The
//! PRG is **exactly** the Davies-Meyer / correlation-robust construction
//! used by [`pcg_core::dpf::prg`] (from `cryprot_core::aes_hash::FIXED_KEY_HASH`,
//! based on Guo et al. 2019):
//!
//! ```text
//!     left_in  = seed ⊕ CONST_L
//!     right_in = seed ⊕ CONST_R
//!     out_L    = AES(FIXED_KEY, left_in) ⊕ left_in
//!     out_R    = AES(FIXED_KEY, right_in) ⊕ right_in
//! ```
//!
//! Matching the single-dealer PRG exactly is **critical**: it's what makes
//! 2-party oblivious gen produce correction words compatible with the
//! existing `pcg_core::dpf::eval_all`. A plain-AES variant would produce
//! garbage keys.
//!
//! Control bits for the DPF tree (one per child) are extracted as the LSB
//! of each output share — see [`PrgShare::t_l`] / [`PrgShare::t_r`].
//!
//! ## Sharing convention
//!
//! - The **input** `seed_share` is an XOR-share: the two parties' shares
//!   XOR to the logical seed.
//! - The **output** `PrgShare` is an XOR-share: the two parties' shares
//!   XOR to the respective AES outputs.
//!
//! Neither party ever sees the logical seed nor the full PRG output.
//!
//! ## Circuit structure
//!
//! All XOR ops are free (Free-XOR optimization in GC). The dominant cost is
//! the two AES-128 garbled calls per session.
//!
//! ```text
//!     seed_xor   = XOR_128(seed_a, seed_b)               # free
//!     in_L       = XOR_128(seed_xor, CONST_L_public)     # free
//!     aes_L      = AES128(FIXED_KEY_public, in_L)        # ~6400 AND gates
//!     out_L      = XOR_128(aes_L, in_L)                  # Davies-Meyer, free
//!     out_L_mask = XOR_128(out_L, mask_L_garbler)        # free
//!     # then for R analogously
//!     decode(out_L_mask), decode(out_R_mask)
//! ```
//!
//! To get XOR-shared outputs, the garbler generates fresh 128-bit random
//! masks at each call. Garbler's share = mask; evaluator's share = decoded.
//!
//! ## OT backing
//!
//! Two modes are supported via separate constructors:
//!
//! - [`Prg2pcSession::new`] — `ideal_cot` with caller-supplied delta.
//!   Fast (no LPN bootstrap). Both parties know the same delta, so this
//!   is **insecure for production** (an evaluator who knows delta can
//!   decrypt the garbler's circuit). Acceptable for correctness testing.
//! - [`Prg2pcSession::new_ferret`] — Ferret silent OT via
//!   `DerandCOTSender/Receiver`. Each call pays the Ferret LPN bootstrap
//!   (~5s), so this is slow for multi-call sessions. **Use case**: single-
//!   DPF validation, and the base for the future session-reuse
//!   optimization (persistent FerretSender across expand calls, not
//!   implemented yet).
//!
//! For production, a session-level persistent Ferret (with Garbler reuse
//! or an Arc<Mutex>-wrapped FerretSender) will be needed. This is a
//! straightforward optimization, documented in
//! `pcg-bn254/docs/OBLIVIOUS_DPF_GEN_DESIGN.md`.

#![cfg(feature = "gc")]

use eyre::Result;
use futures::executor::block_on;
use mpc_net::Network;
use mpz_circuits::{circuits::xor as xor_circuit, AES128};
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_memory_core::{binary::U8, correlated::Delta, Array, MemoryExt, ViewExt};
use mpz_ot::{
    chou_orlandi::{Receiver as ChouOrlandiReceiver, Sender as ChouOrlandiSender},
    cot::{DerandCOTReceiver, DerandCOTSender},
    ferret::{Receiver as FerretReceiver, Sender as FerretSender},
    ideal::{
        cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender},
        rcot::{ideal_rcot, IdealRCOTReceiver, IdealRCOTSender},
    },
    kos::{Receiver as KosReceiver, Sender as KosSender},
};
use mpz_ot_core::{
    ferret::FerretConfig,
    kos::{ReceiverConfig as KosReceiverConfig, SenderConfig as KosSenderConfig},
};
use mpz_vm_core::{Call, CallableExt, Execute};
use once_cell::sync::Lazy;
use pcg_core::pcg::Role;
use rand::{RngCore, SeedableRng};
use spdz_core::ot::async_io::SyncToAsyncIo;
use std::sync::Arc;

/// The AES fixed key used by `cryprot_core::aes_hash::FIXED_KEY_HASH`, which
/// is what `pcg_core::dpf::prg` wraps. Value: little-endian bytes of the u128
/// `193502124791825095790518994062991136444`.
pub const FIXED_KEY: [u8; 16] =
    (193502124791825095790518994062991136444_u128).to_le_bytes();

/// Left-branch XOR constant. Matches `pcg_core::dpf::prg::CONST_L`.
pub const CONST_L: [u8; 16] = [0xA5; 16];
/// Right-branch XOR constant. Matches `pcg_core::dpf::prg::CONST_R`.
pub const CONST_R: [u8; 16] = [0x5A; 16];

/// Lazily-constructed 128-bit XOR boolean circuit. Built once per process.
static XOR_128: Lazy<Arc<mpz_circuits::Circuit>> = Lazy::new(|| Arc::new(xor_circuit(128)));

/// This party's XOR-share of one PRG output pair.
///
/// The logical PRG output is
/// `(AES(K_LEFT, seed_true), AES(K_RIGHT, seed_true))` where
/// `seed_true = seed_share_P0 ⊕ seed_share_P1`. Each party holds one
/// `PrgShare`; XOR-ing the two parties' shares component-wise yields the
/// logical output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrgShare {
    /// This party's XOR-share of `AES(K_LEFT, seed_true)`.
    pub s_l: [u8; 16],
    /// This party's XOR-share of `AES(K_RIGHT, seed_true)`.
    pub s_r: [u8; 16],
}

impl PrgShare {
    /// LSB of the left seed share — this party's XOR-share of the
    /// left-child control bit.
    pub fn t_l(&self) -> bool {
        self.s_l[0] & 1 == 1
    }

    /// LSB of the right seed share — this party's XOR-share of the
    /// right-child control bit.
    pub fn t_r(&self) -> bool {
        self.s_r[0] & 1 == 1
    }
}

/// OT backend for a [`Prg2pcSession`].
#[derive(Debug, Clone, Copy)]
enum CotBackend {
    /// `ideal_cot` with shared delta. Fast (no bootstrap); insecure for
    /// production (both parties know delta).
    Ideal,
    /// Ferret silent OT bootstrapped from `ideal_rcot`. The Garbler/
    /// Evaluator is **persisted across `expand` calls**, so the LPN
    /// bootstrap only happens once (~ms on first call); subsequent
    /// expands reuse the warm state (~ms each).
    ///
    /// Bootstrap uses a local `ideal_rcot` per party — INSECURE delta
    /// handling for production, since both parties effectively share
    /// info about delta.
    Ferret,
    /// **Production OT stack**: Chou-Orlandi (CO15) base OTs → KOS OT
    /// extension (RCOT) → Ferret silent OT (LPN extension). Real
    /// cryptographic OT over the wire — no shared-delta assumption.
    /// First `expand` pays Chou-Orlandi + KOS + Ferret bootstrap
    /// (seconds); subsequent expands sub-ms.
    FerretCO,
}

// ── Type aliases for the Ferret-with-ideal-bootstrap stack ── //

/// Garbler backed by Ferret OT bootstrapped from `ideal_rcot`.
type FerretGb = Garbler<DerandCOTSender<FerretSender<IdealRCOTSender>>>;
type FerretEv = Evaluator<DerandCOTReceiver<FerretReceiver<IdealRCOTReceiver>>>;

struct FerretGbState {
    gb: FerretGb,
    ctx: Context,
}

struct FerretEvState {
    ev: FerretEv,
    ctx: Context,
}

// ── Type aliases for the production Chou-Orlandi → KOS → Ferret stack ── //

/// Production Garbler: full Chou-Orlandi → KOS → Ferret → Derand → Garbler.
type ProdGb = Garbler<DerandCOTSender<FerretSender<KosSender<ChouOrlandiReceiver>>>>;
/// Production Evaluator (mirror of [`ProdGb`]).
type ProdEv = Evaluator<DerandCOTReceiver<FerretReceiver<KosReceiver<ChouOrlandiSender>>>>;

struct ProdGbState {
    gb: ProdGb,
    ctx: Context,
}

struct ProdEvState {
    ev: ProdEv,
    ctx: Context,
}

/// 2PC PRG session — long-lived across many `expand` calls.
///
/// Holds the network handle, shared GC delta, and the chosen OT backend.
/// Each `expand` call creates a fresh [`Garbler`]/[`Evaluator`] pair.
///
/// # Thread safety
///
/// This is not `Send` by itself when the network isn't `Sync`; in practice
/// use within a single thread. Parties run in separate threads, each with
/// their own `Prg2pcSession`.
pub struct Prg2pcSession<N: Network + Unpin + 'static> {
    role: Role,
    net: Arc<N>,
    delta: Block,
    rng: rand_chacha::ChaCha20Rng,
    backend: CotBackend,
    /// Persistent Ferret-backed Garbler state, lazily initialized on
    /// first `expand` (amortizes Ferret LPN bootstrap).
    ferret_gb: Option<FerretGbState>,
    /// Persistent Ferret-backed Evaluator state, lazily initialized.
    ferret_ev: Option<FerretEvState>,
    /// Production-stack Garbler state (Chou-Orlandi → KOS → Ferret).
    prod_gb: Option<ProdGbState>,
    /// Production-stack Evaluator state.
    prod_ev: Option<ProdEvState>,
}

impl<N: Network + Unpin + 'static> Prg2pcSession<N> {
    /// Create a new session backed by `ideal_cot`.
    ///
    /// Both parties must construct with **matching `delta`**. This is
    /// fast (no bootstrap) but **not secure for production** — both
    /// parties know delta, so the evaluator can theoretically decrypt
    /// the garbler's circuit. Use [`Self::new_ferret`] for a production-
    /// grade backend.
    pub fn new(net: Arc<N>, delta: Block) -> Result<Self> {
        Self::new_inner(net, delta, CotBackend::Ideal)
    }

    /// Create a new session backed by Ferret silent OT (via
    /// `DerandCOTSender`/`Receiver` from `mpz-ot`).
    ///
    /// Each `expand` call currently pays the full Ferret LPN bootstrap.
    /// Suitable for validation; production use requires session reuse
    /// (persistent Ferret across expands) — a documented follow-up.
    ///
    /// The `delta` parameter is used only to seed the ideal_rcot
    /// bootstrap. For the RCOT correlations to be consistent between
    /// parties, both must pass matching delta.
    pub fn new_ferret(net: Arc<N>, delta: Block) -> Result<Self> {
        Self::new_inner(net, delta, CotBackend::Ferret)
    }

    fn new_inner(net: Arc<N>, delta: Block, backend: CotBackend) -> Result<Self> {
        let role = match net.id() {
            0 => Role::P0,
            1 => Role::P1,
            other => eyre::bail!("Prg2pcSession requires 2-party net; got id {other}"),
        };
        Ok(Self {
            role,
            net,
            delta,
            rng: rand_chacha::ChaCha20Rng::from_entropy(),
            backend,
            ferret_gb: None,
            ferret_ev: None,
            prod_gb: None,
            prod_ev: None,
        })
    }

    /// Create a new session backed by the **production OT stack**:
    /// Chou-Orlandi (CO15) base OTs → KOS extension → Ferret silent OT.
    ///
    /// This is the only configuration where delta is genuinely secret
    /// to the garbler (the other backends use shared/local delta which
    /// breaks GC privacy in adversarial settings). Each party generates
    /// its OWN local delta; only the garbler's delta affects protocol
    /// semantics, and it's never transmitted.
    ///
    /// First `expand` pays the full Chou-Orlandi (~ms-range, public-key
    /// OT) + KOS extension (~ms) + Ferret LPN (~ms) bootstrap.
    /// Subsequent expands sub-ms.
    pub fn new_ferret_co(net: Arc<N>) -> Result<Self> {
        // Each party generates a local random delta. Garbler's delta is
        // what matters for protocol semantics; evaluator's is unused
        // beyond local KOS state init.
        //
        // CRITICAL: the LSB must be set to 1 (point-and-permute
        // convention enforced by `Delta::new`). If we omit this step,
        // the COT inherits a delta with whatever random LSB, while the
        // Garbler's `Delta::new(self.delta)` silently flips it — and
        // the resulting delta mismatch produces wrong labels and a MAC
        // commitment failure downstream. Caused a real release-mode
        // bug; debug mode happened to work due to slower timing.
        let mut bootstrap_rng = rand_chacha::ChaCha20Rng::from_entropy();
        let mut delta_bytes = [0u8; 16];
        bootstrap_rng.fill_bytes(&mut delta_bytes);
        delta_bytes[0] |= 0x01; // ensure LSB = 1
        Self::new_inner(net, Block::new(delta_bytes), CotBackend::FerretCO)
    }

    /// Return this party's role (P0 garbles, P1 evaluates).
    pub fn role(&self) -> Role {
        self.role
    }

    /// 2PC-expand `seed_share`. Returns this party's XOR-shares of the
    /// left and right PRG outputs.
    ///
    /// Must be called in lock-step with the peer's `expand` on their own
    /// seed share.
    pub fn expand(&mut self, seed_share: [u8; 16]) -> Result<PrgShare> {
        let delta = Delta::new(self.delta);
        let io = SyncToAsyncIo::new(self.net.clone());
        let mut ctx = Context::new_single_threaded(io);

        match (self.role, self.backend) {
            (Role::P0, CotBackend::Ideal) => {
                let (cot_send, _unused) = ideal_cot(self.delta);
                let mut gb = Garbler::new(cot_send, [0u8; 16], delta);
                let (mask_l, mask_r) = self.fresh_masks();
                garbler_expand(&mut gb, &mut ctx, seed_share, mask_l, mask_r)?;
                Ok(PrgShare { s_l: mask_l, s_r: mask_r })
            }
            (Role::P1, CotBackend::Ideal) => {
                let (_unused, cot_recv) = ideal_cot(self.delta);
                let mut ev = Evaluator::new(cot_recv);
                let (s_l, s_r) = evaluator_expand(&mut ev, &mut ctx, seed_share)?;
                Ok(PrgShare { s_l, s_r })
            }
            (Role::P0, CotBackend::Ferret) => {
                // Generate fresh masks before borrowing ferret_gb.
                let (mask_l, mask_r) = self.fresh_masks();
                // Lazily initialize the persistent Garbler on first call.
                // Subsequent calls reuse it — Ferret bootstrap happens only
                // once, in the first execute_all.
                if self.ferret_gb.is_none() {
                    let ferret_s = build_ferret_sender(self.delta, &mut self.rng);
                    let cot_send = DerandCOTSender::new(ferret_s);
                    let gb = Garbler::new(cot_send, [0u8; 16], delta);
                    let io = SyncToAsyncIo::new(self.net.clone());
                    let ctx = Context::new_single_threaded(io);
                    self.ferret_gb = Some(FerretGbState { gb, ctx });
                }
                let st = self.ferret_gb.as_mut().unwrap();
                garbler_expand(&mut st.gb, &mut st.ctx, seed_share, mask_l, mask_r)?;
                Ok(PrgShare { s_l: mask_l, s_r: mask_r })
            }
            (Role::P1, CotBackend::Ferret) => {
                if self.ferret_ev.is_none() {
                    let ferret_r = build_ferret_receiver(self.delta, &mut self.rng);
                    let cot_recv = DerandCOTReceiver::new(ferret_r);
                    let ev = Evaluator::new(cot_recv);
                    let io = SyncToAsyncIo::new(self.net.clone());
                    let ctx = Context::new_single_threaded(io);
                    self.ferret_ev = Some(FerretEvState { ev, ctx });
                }
                let st = self.ferret_ev.as_mut().unwrap();
                let (s_l, s_r) = evaluator_expand(&mut st.ev, &mut st.ctx, seed_share)?;
                Ok(PrgShare { s_l, s_r })
            }
            (Role::P0, CotBackend::FerretCO) => {
                let (mask_l, mask_r) = self.fresh_masks();
                if self.prod_gb.is_none() {
                    let ferret_s = build_prod_ferret_sender(self.delta, &mut self.rng);
                    let cot_send = DerandCOTSender::new(ferret_s);
                    let gb = Garbler::new(cot_send, [0u8; 16], delta);
                    let io = SyncToAsyncIo::new(self.net.clone());
                    let ctx = Context::new_single_threaded(io);
                    self.prod_gb = Some(ProdGbState { gb, ctx });
                }
                let st = self.prod_gb.as_mut().unwrap();
                garbler_expand(&mut st.gb, &mut st.ctx, seed_share, mask_l, mask_r)?;
                Ok(PrgShare { s_l: mask_l, s_r: mask_r })
            }
            (Role::P1, CotBackend::FerretCO) => {
                if self.prod_ev.is_none() {
                    let ferret_r = build_prod_ferret_receiver(&mut self.rng);
                    let cot_recv = DerandCOTReceiver::new(ferret_r);
                    let ev = Evaluator::new(cot_recv);
                    let io = SyncToAsyncIo::new(self.net.clone());
                    let ctx = Context::new_single_threaded(io);
                    self.prod_ev = Some(ProdEvState { ev, ctx });
                }
                let st = self.prod_ev.as_mut().unwrap();
                let (s_l, s_r) = evaluator_expand(&mut st.ev, &mut st.ctx, seed_share)?;
                Ok(PrgShare { s_l, s_r })
            }
        }
    }

    fn fresh_masks(&mut self) -> ([u8; 16], [u8; 16]) {
        let mut mask_l = [0u8; 16];
        self.rng.fill_bytes(&mut mask_l);
        let mut mask_r = [0u8; 16];
        self.rng.fill_bytes(&mut mask_r);
        (mask_l, mask_r)
    }
}

/// Build a fresh Ferret RCOT sender. Bootstrap uses `ideal_rcot(seed, delta)`
/// — both parties must pass the same `delta` for consistency.
fn build_ferret_sender(
    delta: Block,
    rng: &mut impl RngCore,
) -> FerretSender<IdealRCOTSender> {
    let mut bootstrap_seed_bytes = [0u8; 16];
    rng.fill_bytes(&mut bootstrap_seed_bytes);
    let (bootstrap_sender, _unused_recv) =
        ideal_rcot(Block::new(bootstrap_seed_bytes), delta);
    let mut sender_seed_bytes = [0u8; 16];
    rng.fill_bytes(&mut sender_seed_bytes);
    FerretSender::new(
        FerretConfig::default(),
        Block::new(sender_seed_bytes),
        bootstrap_sender,
    )
}

/// Build a fresh Ferret RCOT receiver (peer of [`build_ferret_sender`]).
fn build_ferret_receiver(
    delta: Block,
    rng: &mut impl RngCore,
) -> FerretReceiver<IdealRCOTReceiver> {
    let mut bootstrap_seed_bytes = [0u8; 16];
    rng.fill_bytes(&mut bootstrap_seed_bytes);
    let (_unused_send, bootstrap_receiver) =
        ideal_rcot(Block::new(bootstrap_seed_bytes), delta);
    let mut receiver_seed_bytes = [0u8; 16];
    rng.fill_bytes(&mut receiver_seed_bytes);
    FerretReceiver::new(
        FerretConfig::default(),
        Block::new(receiver_seed_bytes),
        bootstrap_receiver,
    )
}

/// Build the production-stack Ferret RCOT sender:
/// Chou-Orlandi (CO15) base OTs → KOS extension → Ferret silent OT.
///
/// The garbler's `delta` is genuinely secret to this party; the
/// evaluator never sees it (the Chou-Orlandi protocol transmits
/// correlations that are KOS-extended, then Ferret-extended, with
/// delta only present in this party's local state).
fn build_prod_ferret_sender(
    delta: Block,
    rng: &mut impl RngCore,
) -> FerretSender<KosSender<ChouOrlandiReceiver>> {
    // Base OT layer: Chou-Orlandi receiver (KOS sender plays OT
    // receiver in the base layer — KOS sender is the COT receiver).
    let co_recv = ChouOrlandiReceiver::new();
    // KOS extension layer: extends ~128 base OTs to many RCOTs.
    let kos_send = KosSender::new(KosSenderConfig::default(), delta, co_recv);
    // Ferret extension layer: further extends via LPN.
    let mut ferret_seed_bytes = [0u8; 16];
    rng.fill_bytes(&mut ferret_seed_bytes);
    FerretSender::new(
        FerretConfig::default(),
        Block::new(ferret_seed_bytes),
        kos_send,
    )
}

/// Build the production-stack Ferret RCOT receiver (peer of
/// [`build_prod_ferret_sender`]).
fn build_prod_ferret_receiver(
    rng: &mut impl RngCore,
) -> FerretReceiver<KosReceiver<ChouOrlandiSender>> {
    let co_send = ChouOrlandiSender::new();
    let kos_recv = KosReceiver::new(KosReceiverConfig::default(), co_send);
    let mut ferret_seed_bytes = [0u8; 16];
    rng.fill_bytes(&mut ferret_seed_bytes);
    FerretReceiver::new(
        FerretConfig::default(),
        Block::new(ferret_seed_bytes),
        kos_recv,
    )
}

fn garbler_expand<COT>(
    gb: &mut Garbler<COT>,
    ctx: &mut Context,
    seed_share_p0: [u8; 16],
    mask_l: [u8; 16],
    mask_r: [u8; 16],
) -> Result<()>
where
    COT: mpz_ot::cot::COTSender<Block> + mpz_common::Flush + Send + 'static,
    <COT as mpz_ot::cot::COTSender<Block>>::Error: std::error::Error + Send + Sync + 'static,
    <COT as mpz_common::Flush>::Error: std::error::Error + Send + Sync + 'static,
{
    // Inputs
    let seed_a: Array<U8, 16> = gb.alloc().map_err(gc_err)?;
    let seed_b: Array<U8, 16> = gb.alloc().map_err(gc_err)?;
    let fixed_key: Array<U8, 16> = gb.alloc().map_err(gc_err)?;
    let const_l: Array<U8, 16> = gb.alloc().map_err(gc_err)?;
    let const_r: Array<U8, 16> = gb.alloc().map_err(gc_err)?;
    let m_l: Array<U8, 16> = gb.alloc().map_err(gc_err)?;
    let m_r: Array<U8, 16> = gb.alloc().map_err(gc_err)?;
    gb.mark_private(seed_a).map_err(gc_err)?;
    gb.mark_blind(seed_b).map_err(gc_err)?;
    gb.mark_public(fixed_key).map_err(gc_err)?;
    gb.mark_public(const_l).map_err(gc_err)?;
    gb.mark_public(const_r).map_err(gc_err)?;
    gb.mark_private(m_l).map_err(gc_err)?;
    gb.mark_private(m_r).map_err(gc_err)?;

    // seed_xor = seed_a ⊕ seed_b (free)
    let seed_xor: Array<U8, 16> = gb
        .call(Call::builder(XOR_128.clone()).arg(seed_a).arg(seed_b).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    // in_L = seed_xor ⊕ CONST_L; in_R = seed_xor ⊕ CONST_R
    let in_l: Array<U8, 16> = gb
        .call(Call::builder(XOR_128.clone()).arg(seed_xor).arg(const_l).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let in_r: Array<U8, 16> = gb
        .call(Call::builder(XOR_128.clone()).arg(seed_xor).arg(const_r).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    // aes_b = AES(FIXED_KEY, in_b)
    let aes_l: Array<U8, 16> = gb
        .call(Call::builder(AES128.clone()).arg(fixed_key).arg(in_l).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let aes_r: Array<U8, 16> = gb
        .call(Call::builder(AES128.clone()).arg(fixed_key).arg(in_r).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    // Davies-Meyer: out_b = aes_b ⊕ in_b
    let out_l: Array<U8, 16> = gb
        .call(Call::builder(XOR_128.clone()).arg(aes_l).arg(in_l).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let out_r: Array<U8, 16> = gb
        .call(Call::builder(XOR_128.clone()).arg(aes_r).arg(in_r).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    // Mask for shared output
    let out_l_masked: Array<U8, 16> = gb
        .call(Call::builder(XOR_128.clone()).arg(out_l).arg(m_l).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let out_r_masked: Array<U8, 16> = gb
        .call(Call::builder(XOR_128.clone()).arg(out_r).arg(m_r).build().map_err(gc_err)?)
        .map_err(gc_err)?;

    let mut l_fut = gb.decode(out_l_masked).map_err(gc_err)?;
    let mut r_fut = gb.decode(out_r_masked).map_err(gc_err)?;

    // Run preprocess to flush any pending OT setup (Chou-Orlandi base
    // OT exchange, KOS extension setup, Ferret LPN bootstrap). For the
    // ideal_cot/ideal_rcot backends this is essentially a no-op.
    if gb.wants_preprocess() {
        block_on(gb.preprocess(ctx)).map_err(gc_err)?;
    }

    gb.assign(seed_a, seed_share_p0).map_err(gc_err)?;
    gb.assign(fixed_key, FIXED_KEY).map_err(gc_err)?;
    gb.assign(const_l, CONST_L).map_err(gc_err)?;
    gb.assign(const_r, CONST_R).map_err(gc_err)?;
    gb.assign(m_l, mask_l).map_err(gc_err)?;
    gb.assign(m_r, mask_r).map_err(gc_err)?;
    gb.commit(seed_a).map_err(gc_err)?;
    gb.commit(seed_b).map_err(gc_err)?;
    gb.commit(fixed_key).map_err(gc_err)?;
    gb.commit(const_l).map_err(gc_err)?;
    gb.commit(const_r).map_err(gc_err)?;
    gb.commit(m_l).map_err(gc_err)?;
    gb.commit(m_r).map_err(gc_err)?;

    block_on(gb.execute_all(ctx)).map_err(gc_err)?;

    // Drain futures — garbler doesn't use the decoded values (its shares ARE the masks).
    l_fut
        .try_recv()
        .map_err(gc_err)?
        .ok_or_else(|| eyre::eyre!("garbler: decode left did not complete"))?;
    r_fut
        .try_recv()
        .map_err(gc_err)?
        .ok_or_else(|| eyre::eyre!("garbler: decode right did not complete"))?;
    Ok(())
}

fn evaluator_expand<COT>(
    ev: &mut Evaluator<COT>,
    ctx: &mut Context,
    seed_share_p1: [u8; 16],
) -> Result<([u8; 16], [u8; 16])>
where
    COT: mpz_ot::cot::COTReceiver<bool, Block> + mpz_common::Flush + Send + 'static,
    <COT as mpz_ot::cot::COTReceiver<bool, Block>>::Error: std::error::Error + Send + Sync + 'static,
    <COT as mpz_common::Flush>::Error: std::error::Error + Send + Sync + 'static,
{
    let seed_a: Array<U8, 16> = ev.alloc().map_err(gc_err)?;
    let seed_b: Array<U8, 16> = ev.alloc().map_err(gc_err)?;
    let fixed_key: Array<U8, 16> = ev.alloc().map_err(gc_err)?;
    let const_l: Array<U8, 16> = ev.alloc().map_err(gc_err)?;
    let const_r: Array<U8, 16> = ev.alloc().map_err(gc_err)?;
    let m_l: Array<U8, 16> = ev.alloc().map_err(gc_err)?;
    let m_r: Array<U8, 16> = ev.alloc().map_err(gc_err)?;
    ev.mark_blind(seed_a).map_err(gc_err)?;
    ev.mark_private(seed_b).map_err(gc_err)?;
    ev.mark_public(fixed_key).map_err(gc_err)?;
    ev.mark_public(const_l).map_err(gc_err)?;
    ev.mark_public(const_r).map_err(gc_err)?;
    ev.mark_blind(m_l).map_err(gc_err)?;
    ev.mark_blind(m_r).map_err(gc_err)?;

    let seed_xor: Array<U8, 16> = ev
        .call(Call::builder(XOR_128.clone()).arg(seed_a).arg(seed_b).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let in_l: Array<U8, 16> = ev
        .call(Call::builder(XOR_128.clone()).arg(seed_xor).arg(const_l).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let in_r: Array<U8, 16> = ev
        .call(Call::builder(XOR_128.clone()).arg(seed_xor).arg(const_r).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let aes_l: Array<U8, 16> = ev
        .call(Call::builder(AES128.clone()).arg(fixed_key).arg(in_l).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let aes_r: Array<U8, 16> = ev
        .call(Call::builder(AES128.clone()).arg(fixed_key).arg(in_r).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let out_l: Array<U8, 16> = ev
        .call(Call::builder(XOR_128.clone()).arg(aes_l).arg(in_l).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let out_r: Array<U8, 16> = ev
        .call(Call::builder(XOR_128.clone()).arg(aes_r).arg(in_r).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let out_l_masked: Array<U8, 16> = ev
        .call(Call::builder(XOR_128.clone()).arg(out_l).arg(m_l).build().map_err(gc_err)?)
        .map_err(gc_err)?;
    let out_r_masked: Array<U8, 16> = ev
        .call(Call::builder(XOR_128.clone()).arg(out_r).arg(m_r).build().map_err(gc_err)?)
        .map_err(gc_err)?;

    let mut l_fut = ev.decode(out_l_masked).map_err(gc_err)?;
    let mut r_fut = ev.decode(out_r_masked).map_err(gc_err)?;

    if ev.wants_preprocess() {
        block_on(ev.preprocess(ctx)).map_err(gc_err)?;
    }

    ev.assign(seed_b, seed_share_p1).map_err(gc_err)?;
    ev.assign(fixed_key, FIXED_KEY).map_err(gc_err)?;
    ev.assign(const_l, CONST_L).map_err(gc_err)?;
    ev.assign(const_r, CONST_R).map_err(gc_err)?;
    ev.commit(seed_a).map_err(gc_err)?;
    ev.commit(seed_b).map_err(gc_err)?;
    ev.commit(fixed_key).map_err(gc_err)?;
    ev.commit(const_l).map_err(gc_err)?;
    ev.commit(const_r).map_err(gc_err)?;
    ev.commit(m_l).map_err(gc_err)?;
    ev.commit(m_r).map_err(gc_err)?;

    block_on(ev.execute_all(ctx)).map_err(gc_err)?;

    let s_l = l_fut
        .try_recv()
        .map_err(gc_err)?
        .ok_or_else(|| eyre::eyre!("evaluator: decode left did not complete"))?;
    let s_r = r_fut
        .try_recv()
        .map_err(gc_err)?
        .ok_or_else(|| eyre::eyre!("evaluator: decode right did not complete"))?;
    Ok((s_l, s_r))
}

fn gc_err<E: std::fmt::Display>(e: E) -> eyre::Error {
    eyre::eyre!("gc: {e}")
}
