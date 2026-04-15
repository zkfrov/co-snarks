//! 2-party OLE generation protocol abstraction.
//!
//! Given each party's private polynomial `a_i` (length N, coefficient form),
//! the protocol produces each party's share `c_i` such that:
//!
//!   c_0 + c_1  =  a_0 * a_1   (cyclic convolution in F[X]/(X^N - 1))
//!
//! The `expand` step of the PCG then FFT-transforms both (a_i, c_i) into
//! evaluation form, yielding N OLE correlations per party.
//!
//! This module provides:
//! - `OleProtocol` trait (abstraction)
//! - `MockOleProtocol` (insecure, channel-based; for tests and development)
//!
//! Real OT-based protocols are added in Phase 2a.1 — they implement this
//! same trait.

use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use eyre::Result;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use crate::pcg::Role;

/// A 2-party cyclic-convolution OLE protocol.
pub trait OleProtocol<F: PrimeField + FftField>: Send {
    /// Compute this party's share of the cyclic convolution with the peer's
    /// polynomial. Must be called with matching `log_n` on both sides.
    fn cyclic_conv_share(
        &mut self,
        my_a: &[F],
        log_n: usize,
    ) -> Result<Vec<F>>;
}

// ─────────────────────────── MockOleProtocol ─────────────────────────── //

/// Insecure mock protocol: both parties submit their polynomials through a
/// shared state, one side computes the full convolution, and both sides get
/// their shares back.
///
/// Useful for testing and for validating the PcgPreprocessing refactor
/// without yet depending on OT implementations. **NOT cryptographically
/// secure** — all values pass through shared memory.
pub struct MockOleProtocol<F: PrimeField + FftField> {
    role: Role,
    shared: Arc<Mutex<MockState<F>>>,
}

/// Shared state held by both `MockOleProtocol` ends.
struct MockState<F: PrimeField + FftField> {
    /// Polynomial submitted by P0 (if any, awaiting pairing).
    p0_poly: Option<Vec<F>>,
    /// Polynomial submitted by P1 (if any, awaiting pairing).
    p1_poly: Option<Vec<F>>,
    /// Result ready for P0: c_0 share.
    p0_result_tx: Option<mpsc::Sender<Vec<F>>>,
    /// Result ready for P1: c_1 share.
    p1_result_tx: Option<mpsc::Sender<Vec<F>>>,
    /// Random mask (c_0 share) — the full product minus mask is c_1.
    /// We re-seed mask PRG internally; not exposed.
    mask_seed: u64,
    /// Sequence counter so each call is independent.
    seq: u64,
}

impl<F: PrimeField + FftField> MockOleProtocol<F> {
    /// Create a paired `(p0, p1)` mock protocol.
    pub fn new_pair(mask_seed: u64) -> (Self, Self) {
        let shared = Arc::new(Mutex::new(MockState {
            p0_poly: None,
            p1_poly: None,
            p0_result_tx: None,
            p1_result_tx: None,
            mask_seed,
            seq: 0,
        }));
        (
            Self {
                role: Role::P0,
                shared: shared.clone(),
            },
            Self {
                role: Role::P1,
                shared,
            },
        )
    }
}

/// Cyclic convolution via FFT on size-N domain.
fn cyclic_conv<F: PrimeField + FftField>(a: &[F], b: &[F]) -> Vec<F> {
    debug_assert_eq!(a.len(), b.len());
    let n = a.len();
    let domain = Radix2EvaluationDomain::<F>::new(n)
        .expect("FFT domain of size N must exist for BN254");
    let mut ea = a.to_vec();
    let mut eb = b.to_vec();
    domain.fft_in_place(&mut ea);
    domain.fft_in_place(&mut eb);
    for (x, y) in ea.iter_mut().zip(eb.iter()) {
        *x *= y;
    }
    domain.ifft_in_place(&mut ea);
    ea
}

impl<F: PrimeField + FftField> OleProtocol<F> for MockOleProtocol<F> {
    fn cyclic_conv_share(&mut self, my_a: &[F], log_n: usize) -> Result<Vec<F>> {
        let n = 1usize << log_n;
        if my_a.len() != n {
            eyre::bail!("my_a length {} != expected {}", my_a.len(), n);
        }

        // Register this party's polynomial and channel. When both parties
        // have submitted, the LATER arrival computes the convolution and
        // sends each side its share.
        let (tx, rx) = mpsc::channel::<Vec<F>>();
        {
            let mut st = self.shared.lock().unwrap();
            match self.role {
                Role::P0 => {
                    st.p0_poly = Some(my_a.to_vec());
                    st.p0_result_tx = Some(tx);
                }
                Role::P1 => {
                    st.p1_poly = Some(my_a.to_vec());
                    st.p1_result_tx = Some(tx);
                }
            }
            if st.p0_poly.is_some() && st.p1_poly.is_some() {
                // Both sides have submitted — compute convolution and shares.
                use rand::SeedableRng;
                let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(
                    st.mask_seed.wrapping_add(st.seq.wrapping_mul(0xA11CE)),
                );
                st.seq = st.seq.wrapping_add(1);
                let a0 = st.p0_poly.take().unwrap();
                let a1 = st.p1_poly.take().unwrap();
                let prod = cyclic_conv::<F>(&a0, &a1);
                let c0: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
                let c1: Vec<F> = prod.iter().zip(c0.iter()).map(|(p, m)| *p - *m).collect();
                let tx0 = st.p0_result_tx.take().unwrap();
                let tx1 = st.p1_result_tx.take().unwrap();
                tx0.send(c0).ok();
                tx1.send(c1).ok();
            }
        }

        // Block on the result sent by whichever side computed.
        let c = rx
            .recv()
            .map_err(|e| eyre::eyre!("mock protocol channel error: {e}"))?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::UniformRand;
    use rand::SeedableRng;

    #[test]
    fn test_mock_ole_protocol_cyclic() {
        let (mut p0, mut p1) = MockOleProtocol::<Fr>::new_pair(42);

        let log_n = 8;
        let n = 1usize << log_n;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let a0: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let a1: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let a0_clone = a0.clone();
        let a1_clone = a1.clone();

        let h0 = std::thread::spawn(move || p0.cyclic_conv_share(&a0_clone, log_n).unwrap());
        let h1 = std::thread::spawn(move || p1.cyclic_conv_share(&a1_clone, log_n).unwrap());

        let c0 = h0.join().unwrap();
        let c1 = h1.join().unwrap();

        // Verify: c_0 + c_1 = a_0 * a_1 (cyclic conv)
        let expected = cyclic_conv::<Fr>(&a0, &a1);
        let actual: Vec<Fr> = c0.iter().zip(c1.iter()).map(|(x, y)| *x + *y).collect();
        assert_eq!(actual, expected, "mock OLE protocol convolution invariant");
    }
}
