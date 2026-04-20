//! Oblivious 2-party DMPF generation (sum-of-DPFs variant).
//!
//! The oblivious analog of [`pcg_protocols::dmpf_gen_sum_of_dpfs`]. Runs
//! t² oblivious [`dpf_gen_oblivious_additive_alpha`] calls on a single
//! shared [`Prg2pcSession`], so the Ferret LPN bootstrap is amortized
//! across all DPFs in the DMPF.
//!
//! ## Performance
//!
//! Per DMPF with t² DPFs at log_n:
//!   - 1× Ferret bootstrap (~113 ms)
//!   - t² × (per-DPF work: ~2·log_n expands @ ~1.8 ms + leaf correction)
//!
//! At log_n=20, t=64: 4096 × ~85 ms ≈ **~6 min sequential / ~45 sec on 8
//! cores** for one DMPF. A full PCG batch has 4 cross-term DMPFs.
//!
//! ## API shape
//!
//! Mirrors `pcg_protocols::dmpf_gen_sum_of_dpfs` but with an extra
//! `prg_session: &mut Prg2pcSession<N>` parameter, since oblivious gen
//! needs the 2PC PRG.

#![cfg(feature = "gc")]

use ark_ff::PrimeField;
use eyre::Result;
use mpc_net::Network;
use pcg_core::dpf::DpfKey;
use pcg_core::pcg::Role;
use pcg_core::sparse::SparsePoly;
use pcg_protocols::{BitOt, SumOfDpfsKey};
use rand::RngCore;

use crate::dpf_oblivious::dpf_gen_oblivious_additive_alpha;
use crate::prg_2pc::Prg2pcSession;

/// 2-party oblivious sum-of-DPFs DMPF generation.
///
/// Same semantics and output format as
/// [`pcg_protocols::dmpf_gen_sum_of_dpfs`]: produces a `SumOfDpfsKey<F>`
/// containing t² DPFs whose combined evaluation (via `eval_all`) matches
/// the cyclic convolution of the two parties' sparse polynomials.
///
/// # Security
///
/// No party learns α = (p_i + q_j) mod N for any (i, j). Each DPF's α is
/// kept secret via the oblivious gen protocol.
///
/// # Inputs
///
/// Same as `pcg_protocols::dmpf_gen_sum_of_dpfs`, plus:
/// - `prg_session`: a [`Prg2pcSession`] (shared across all inner DPFs
///   for bootstrap amortization).
pub fn dmpf_gen_oblivious<F, N, OT>(
    prg_session: &mut Prg2pcSession<N>,
    ot: &mut OT,
    role: Role,
    my_sparse: &SparsePoly<F>,
    peer_sparse_len: usize,
    log_n: u32,
) -> Result<SumOfDpfsKey<F>>
where
    F: PrimeField,
    N: Network + Unpin + 'static,
    OT: BitOt,
{
    let my_len = my_sparse.entries.len();

    // Iteration bounds: outer loop = P0's length, inner = P1's length.
    // Both parties iterate pairs in the same order (index-based).
    let outer = match role {
        Role::P0 => my_len,
        Role::P1 => peer_sparse_len,
    };
    let inner = match role {
        Role::P0 => peer_sparse_len,
        Role::P1 => my_len,
    };
    let total = outer * inner;

    let mut dpfs: Vec<DpfKey<F>> = Vec::with_capacity(total);
    let mut rng = rand::thread_rng();

    for p0_idx in 0..outer {
        for p1_idx in 0..inner {
            let (alpha_share, beta_share) = match role {
                Role::P0 => {
                    let (pos, val) = my_sparse.entries[p0_idx];
                    (pos as u64, val)
                }
                Role::P1 => {
                    let (pos, val) = my_sparse.entries[p1_idx];
                    (pos as u64, val)
                }
            };
            let alpha_masked = alpha_share & ((1u64 << log_n) - 1);

            // Fresh random root per DPF (per party).
            let mut root = [0u8; 16];
            rng.fill_bytes(&mut root);

            let dpf = dpf_gen_oblivious_additive_alpha::<F, N, OT>(
                prg_session,
                ot,
                role,
                alpha_masked,
                beta_share,
                root,
                log_n,
            )?;
            dpfs.push(dpf);
        }
    }

    Ok(SumOfDpfsKey { log_n, dpfs })
}

// ────────────────── 2-party Ring-LPN PCG seed gen ────────────────── //

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use pcg_core::ring_lpn::{cyclic_conv_dense, lpn_expand};
use pcg_core::ring_lpn_pcg::RingLpnPcgParams;

/// Oblivious 2-party Ring-LPN PCG seed.
///
/// Same layout as `pcg_protocols::Seed2Party` — each party holds its own
/// sparse `s`, `e` + 4 `SumOfDpfsKey`s for the cross-terms — but
/// generated via the oblivious DPF gen (no α leak).
pub struct Seed2PartyOblivious<F: PrimeField + FftField> {
    pub role: Role,
    pub params: RingLpnPcgParams<F>,
    pub s: SparsePoly<F>,
    pub e: SparsePoly<F>,
    pub dmpf_ss: SumOfDpfsKey<F>,
    pub dmpf_se: SumOfDpfsKey<F>,
    pub dmpf_es: SumOfDpfsKey<F>,
    pub dmpf_ee: SumOfDpfsKey<F>,
}

impl<F: PrimeField + FftField> Seed2PartyOblivious<F> {
    /// Local expansion: produces `(a_coeff, c_coeff)` in coefficient form,
    /// each of length N.
    ///
    /// Same math as `pcg_protocols::Seed2Party::expand`:
    ///   a = u + e where u = a · s (cyclic conv, LPN)
    ///   c = a² · ss + a · se + a · es + ee
    pub fn expand(&self) -> (Vec<F>, Vec<F>) {
        let n = self.params.n();
        let u = lpn_expand(&self.params.a, &self.s);
        let mut a_poly = u;
        for (pos, val) in &self.e.entries {
            a_poly[*pos] += *val;
        }
        let share_ss = self.dmpf_ss.eval_all();
        let share_se = self.dmpf_se.eval_all();
        let share_es = self.dmpf_es.eval_all();
        let share_ee = self.dmpf_ee.eval_all();
        let term_ss = cyclic_conv_dense(&self.params.a_sq, &share_ss);
        let term_se = cyclic_conv_dense(&self.params.a, &share_se);
        let term_es = cyclic_conv_dense(&self.params.a, &share_es);
        let mut c = vec![F::zero(); n];
        for i in 0..n {
            c[i] = term_ss[i] + term_se[i] + term_es[i] + share_ee[i];
        }
        (a_poly, c)
    }

    /// Convenience: FFT to eval form, return N pointwise OLE correlations.
    pub fn expand_to_ole(&self) -> Vec<(F, F)> {
        let n = self.params.n();
        let (mut a_poly, mut c) = self.expand();
        let domain =
            Radix2EvaluationDomain::<F>::new(n).expect("FFT domain of size N must exist");
        domain.fft_in_place(&mut a_poly);
        domain.fft_in_place(&mut c);
        a_poly.into_iter().zip(c.into_iter()).collect()
    }
}

/// Oblivious 2-party Ring-LPN PCG seed generation.
///
/// Runs 4 [`dmpf_gen_oblivious`] calls (one per cross-term s·s, s·e,
/// e·s, e·e) on a shared [`Prg2pcSession`] — the Ferret LPN bootstrap
/// happens ONCE for the whole PCG gen, amortizing across all t² × 4
/// inner DPFs.
///
/// Mirrors `pcg_protocols::gen_seed_2party` (the leaky version), with
/// the added `prg_session` parameter.
pub fn gen_seed_2party_oblivious<F, N, OT>(
    prg_session: &mut Prg2pcSession<N>,
    ot: &mut OT,
    role: Role,
    params: RingLpnPcgParams<F>,
    my_s: SparsePoly<F>,
    my_e: SparsePoly<F>,
) -> Result<Seed2PartyOblivious<F>>
where
    F: PrimeField + FftField,
    N: Network + Unpin + 'static,
    OT: BitOt,
{
    let log_n = params.log_n;
    let peer_t = params.t;

    // Match gen_seed_2party's per-role cross-term input selection:
    //   cross-term s·s: P0 submits s, P1 submits s
    //   cross-term s·e: P0 submits s, P1 submits e
    //   cross-term e·s: P0 submits e, P1 submits s
    //   cross-term e·e: P0 submits e, P1 submits e
    let (ss_in, se_in, es_in, ee_in) = match role {
        Role::P0 => (&my_s, &my_s, &my_e, &my_e),
        Role::P1 => (&my_s, &my_e, &my_s, &my_e),
    };

    let dmpf_ss = dmpf_gen_oblivious::<F, N, OT>(prg_session, ot, role, ss_in, peer_t, log_n)?;
    let dmpf_se = dmpf_gen_oblivious::<F, N, OT>(prg_session, ot, role, se_in, peer_t, log_n)?;
    let dmpf_es = dmpf_gen_oblivious::<F, N, OT>(prg_session, ot, role, es_in, peer_t, log_n)?;
    let dmpf_ee = dmpf_gen_oblivious::<F, N, OT>(prg_session, ot, role, ee_in, peer_t, log_n)?;

    Ok(Seed2PartyOblivious {
        role,
        params,
        s: my_s,
        e: my_e,
        dmpf_ss,
        dmpf_se,
        dmpf_es,
        dmpf_ee,
    })
}
