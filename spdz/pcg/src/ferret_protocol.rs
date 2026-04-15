//! Ferret-based OleProtocol implementation.
//!
//! Runs N pointwise OLEs between two parties using mpz's Ferret silent OT
//! (wrapped in spdz-core). Each party contributes a length-N vector; each
//! party receives their additive share of the pointwise product vector.
//!
//! Implementation note: this module wraps `spdz_core::ot::ferret::gilboa_send`
//! and `gilboa_recv` which internally use Silent OT extension + Gilboa
//! conversion (BIT_SIZE RCOTs per field element). Communication is the
//! standard Gilboa cost — BIT_SIZE × 32 bytes of τ per OLE.

use crate::pcg::Role;
use crate::protocol::OleProtocol;
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use eyre::Result;
use mpc_net::Network;
use spdz_core::ot::ferret::{gilboa_recv, gilboa_send, FerretSession};
use std::sync::Arc;

pub struct FerretOleProtocol<N: Network + Unpin + 'static> {
    session: FerretSession<N>,
    net: Arc<N>,
    role: Role,
}

impl<N: Network + Unpin + 'static> FerretOleProtocol<N> {
    /// Create the protocol for this party. Performs Ferret init (seed exchange
    /// with the peer).
    pub fn new(net: Arc<N>) -> Result<Self> {
        let role = match net.id() {
            0 => Role::P0,
            1 => Role::P1,
            other => eyre::bail!("unexpected party id {other}"),
        };
        let session = FerretSession::new(net.clone())?;
        Ok(Self { session, net, role })
    }
}

impl<F, N> OleProtocol<F> for FerretOleProtocol<N>
where
    F: PrimeField + FftField,
    N: Network + Unpin + 'static,
{
    fn cyclic_conv_share(&mut self, my_a: &[F], log_n: usize) -> Result<Vec<F>> {
        let n = 1usize << log_n;
        if my_a.len() != n {
            eyre::bail!("my_a length {} != expected {}", my_a.len(), n);
        }

        // Step 1: FFT my_a to evaluation form. In eval form, cyclic convolution
        // becomes pointwise product — so we just need N pointwise OLEs.
        let domain = Radix2EvaluationDomain::<F>::new(n)
            .ok_or_else(|| eyre::eyre!("FFT domain of size {n} unavailable"))?;
        let mut a_eval = my_a.to_vec();
        domain.fft_in_place(&mut a_eval);

        // Step 2: Run the N pointwise OLEs via Gilboa (Ferret under the hood).
        // P0 plays the sender role, P1 the receiver role. Both receive their
        // additive share of the pointwise product in eval form.
        let c_eval = match self.role {
            Role::P0 => gilboa_send(&mut self.session, &*self.net, &a_eval)?,
            Role::P1 => gilboa_recv(&mut self.session, &*self.net, &a_eval)?,
        };

        // Step 3: IFFT c_eval back to coefficient form. PcgSeed::expand will
        // FFT again — slightly wasteful, but matches the trait contract.
        let mut c_coeff = c_eval;
        domain.ifft_in_place(&mut c_coeff);

        Ok(c_coeff)
    }
}
