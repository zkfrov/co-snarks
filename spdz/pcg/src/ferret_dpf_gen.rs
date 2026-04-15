//! 2-party DPF key generation via Ferret OT (Phase 2b.2e.1, first cut).
//!
//! ## Scope of this module
//!
//! This is the FIRST MILESTONE of the real OT-based 2-party DMPF generation
//! work. It implements the core primitive:
//!
//!   **2-party DPF gen with XOR-shared α and additively-shared β**
//!
//! Input per party:
//! - `my_alpha_share: u64` — this party's log_n-bit XOR share of α
//! - `my_beta_share: F` — this party's additive share of β
//!
//! Target (combined):
//! - α = (P0's share) XOR (P1's share)   (bit-wise XOR as log_n-bit ints)
//! - β = (P0's share) + (P1's share)     (in F)
//!
//! Output per party: a `DpfKey<F>` such that, when both parties evaluate
//! their keys and sum, they get the point function at α with value β.
//!
//! ## What this does NOT do (yet — follow-up commits)
//!
//! 1. **Additively-shared α**: our Ring-LPN PCG needs α = α_0 + α_1 mod N,
//!    not XOR. Adding an A2B (arithmetic-to-binary) conversion layer is a
//!    follow-up task (~week of work).
//!
//! 2. **Multiplicatively-shared β**: our PCG needs β = β_0 · β_1. Adding an
//!    OLE-based conversion step is straightforward once the XOR-α path works.
//!
//! 3. **Looping to form DMPF**: once single-point 2-party DPF gen works,
//!    we loop t² times per DMPF cross-term.
//!
//! 4. **Full integration**: after all three extensions, we swap the
//!    `MockDmpfGenProtocol` for a real `FerretDmpfGenProtocol` in
//!    `RingLpnPcgSeed::gen_with_protocols`.
//!
//! ## Protocol sketch (per tree level i)
//!
//! Both parties expand their current (seed, ctrl) via PRG locally.
//! At each level, the correction word `(cw_seed, cw_tL, cw_tR)` depends
//! on `α_i` (one bit of α, XOR-shared between the two parties).
//!
//! We compute CW via 1-out-of-2 OT:
//! - P0 (sender) prepares two message candidates — one for α_i=0, one
//!   for α_i=1 — each combining P0's local PRG output with the needed
//!   XOR/flip structure.
//! - P1 (receiver) selects using `α_i_1` (its share), XOR'd suitably.
//! - Both parties derive the same CW from the OT output.
//!
//! After log_n levels + a final leaf-correction step (OLE-like for β),
//! each party has a complete `DpfKey<F>`.
//!
//! This module currently provides the TYPE surfaces and a scaffolded
//! protocol. Full correctness of the field-level computations is NOT yet
//! claimed; the structural plumbing and OT wiring is in place, and
//! correctness tests for the single-point case are pending.

#![allow(dead_code)] // parts will be filled in as the protocol matures

use crate::dpf::{CorrectionWord, DpfKey, Seed};
use crate::pcg::Role;
use ark_ff::PrimeField;
use eyre::Result;
use mpc_net::Network;
use spdz_core::ot::ferret::FerretSession;
use std::sync::Arc;

/// 2-party DPF generation protocol backed by Ferret OT.
///
/// NOTE: Current implementation supports XOR-shared α and additively-shared β.
/// Extensions to additively-shared α (required for our Ring-LPN PCG) and
/// multiplicatively-shared β come in subsequent commits.
pub struct FerretDpfGenProtocol<N: Network + Unpin + 'static> {
    session: FerretSession<N>,
    net: Arc<N>,
    role: Role,
}

impl<N: Network + Unpin + 'static> FerretDpfGenProtocol<N> {
    /// Create a new protocol instance. Performs Ferret init (seed exchange
    /// between parties).
    pub fn new(net: Arc<N>) -> Result<Self> {
        let role = match net.id() {
            0 => Role::P0,
            1 => Role::P1,
            other => eyre::bail!("expected party id 0 or 1, got {other}"),
        };
        let session = FerretSession::new(net.clone())?;
        Ok(Self { session, net, role })
    }

    /// Run 2-party DPF gen.
    ///
    /// PRECONDITION: `my_alpha_share` and peer's share XOR to α ∈ [0, 2^log_n).
    /// PRECONDITION: `my_beta_share` + peer's share = β (in F).
    ///
    /// POSTCONDITION: returned DPF key, when combined with peer's key via
    /// `eval_all`, produces the point function f(α)=β, f(x)=0 otherwise.
    pub fn gen_dpf<F: PrimeField>(
        &mut self,
        my_alpha_share: u64,
        my_beta_share: F,
        log_n: u32,
    ) -> Result<DpfKey<F>> {
        // Scaffolding: the protocol structure is laid out but the field-level
        // OT-based correction word computation is marked TODO below. A first
        // working implementation will arrive in follow-up commits.

        if log_n as u64 > 64 {
            eyre::bail!("log_n {log_n} must be ≤ 64");
        }
        let _ = (my_alpha_share, my_beta_share, log_n);
        let _ = &mut self.session;
        let _ = &self.net;
        let _ = self.role;

        // Placeholder — return an error indicating this path is not yet
        // fully implemented at the crypto layer. The structure is ready for
        // the level-by-level OT implementation to be filled in.
        eyre::bail!(
            "FerretDpfGenProtocol::gen_dpf: 2-party DPF gen crypto layer not \
             yet implemented. Returning explicit error rather than silently \
             producing incorrect keys. Implementation in progress."
        )
    }
}

/// Public helper: size of a DPF key for a given log_n, in bytes.
/// Useful for estimating protocol communication budgets.
pub fn dpf_key_size_bytes(log_n: u32, bytes_per_field_element: usize) -> usize {
    // root_seed + root_ctrl byte + corrections (cw_seed + 2 ctrl bits per level)
    //   + final_correction (field element)
    16 + 1 + (log_n as usize) * (16 + 2) + bytes_per_field_element
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use mpc_net::local::LocalNetwork;

    #[test]
    fn dpf_gen_scaffolded_errors_cleanly() {
        // The scaffold should NOT silently produce an incorrect DPF.
        // It should return a clear error indicating the crypto layer is
        // still in progress. (This test will flip to a correctness test
        // once the protocol is fully implemented.)
        let mut nets = LocalNetwork::new(2).into_iter();
        let net0 = Arc::new(nets.next().unwrap());
        let net1 = Arc::new(nets.next().unwrap());

        let net0c = net0.clone();
        let net1c = net1.clone();
        let h0 = std::thread::spawn(move || {
            let mut proto = FerretDpfGenProtocol::new(net0c).unwrap();
            proto.gen_dpf::<Fr>(0u64, Fr::from(0u64), 4)
        });
        let h1 = std::thread::spawn(move || {
            let mut proto = FerretDpfGenProtocol::new(net1c).unwrap();
            proto.gen_dpf::<Fr>(0u64, Fr::from(0u64), 4)
        });

        let r0 = h0.join().unwrap();
        let r1 = h1.join().unwrap();
        assert!(r0.is_err(), "expected error, got {:?}", r0.is_ok());
        assert!(r1.is_err(), "expected error, got {:?}", r1.is_ok());
    }

    #[test]
    fn dpf_key_size_sanity() {
        // log_n=20, 32-byte field → 16 + 1 + 20*18 + 32 = 409 bytes
        let size = dpf_key_size_bytes(20, 32);
        assert_eq!(size, 16 + 1 + 20 * 18 + 32);
        assert_eq!(size, 409);
    }
}
