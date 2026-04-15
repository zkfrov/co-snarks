//! 2-party DMPF key generation protocol.
//!
//! Each party provides its half of the sparse product input; the protocol
//! produces each party's DMPF key encoding the cyclic convolution of the
//! two sparse vectors.
//!
//! Phase 2b.2e.0 provides:
//! - `DmpfGenProtocol` trait (API surface)
//! - `MockDmpfGenProtocol` — channel-based, insecure; for testing the
//!   structural integration of 2-party DMPF gen into `RingLpnPcgSeed`
//!
//! The real OT-based protocol (Phase 2b.2e.1) will implement this same
//! trait. Real construction: for each pair of non-zero entries (p_i, v_i)
//! in P0's input and (q_j, w_j) in P1's input, run a 2-party DPF gen
//! protocol that produces keys for a point function at α = (p_i + q_j) mod N
//! with value β = v_i · w_j. Uses OT for the tree-level correction words.

use crate::dmpf::{gen_dmpf, DmpfKey};
use crate::pcg::Role;
use crate::ring_lpn::sparse_cyclic_mul_dense;
use crate::sparse::SparsePoly;
use ark_ff::PrimeField;
use eyre::Result;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// 2-party DMPF generation protocol.
///
/// Both parties call `gen_dmpf_share` with their OWN sparse input vector;
/// the protocol coordinates across parties to produce matching DMPF keys
/// that encode the cyclic convolution of the two inputs.
pub trait DmpfGenProtocol<F: PrimeField>: Send {
    /// Produce this party's DMPF key for the product of its own sparse input
    /// with the peer's sparse input (which the peer submits separately).
    fn gen_dmpf_share(
        &mut self,
        my_sparse: &SparsePoly<F>,
        log_n: u32,
    ) -> Result<DmpfKey<F>>;
}

// ────────────────────────── MockDmpfGenProtocol ────────────────────────── //

/// Insecure mock protocol: both parties submit their sparse vectors through
/// shared memory, and the mock produces matching DMPF keys by running the
/// trusted-dealer `gen_dmpf` centrally.
///
/// Useful for validating structural integration. **NOT cryptographically
/// secure** — shared memory means either party's state reveals the other's.
pub struct MockDmpfGenProtocol<F: PrimeField> {
    role: Role,
    shared: Arc<Mutex<MockState<F>>>,
}

struct MockState<F: PrimeField> {
    p0_input: Option<SparsePoly<F>>,
    p1_input: Option<SparsePoly<F>>,
    p0_result_tx: Option<mpsc::Sender<DmpfKey<F>>>,
    p1_result_tx: Option<mpsc::Sender<DmpfKey<F>>>,
    seq: u64,
    rng_seed: u64,
}

impl<F: PrimeField> MockDmpfGenProtocol<F> {
    /// Create a paired `(p0, p1)` mock protocol.
    pub fn new_pair(rng_seed: u64) -> (Self, Self) {
        let shared = Arc::new(Mutex::new(MockState {
            p0_input: None,
            p1_input: None,
            p0_result_tx: None,
            p1_result_tx: None,
            seq: 0,
            rng_seed,
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

impl<F: PrimeField> DmpfGenProtocol<F> for MockDmpfGenProtocol<F> {
    fn gen_dmpf_share(
        &mut self,
        my_sparse: &SparsePoly<F>,
        log_n: u32,
    ) -> Result<DmpfKey<F>> {
        let (tx, rx) = mpsc::channel::<DmpfKey<F>>();
        {
            let mut st = self.shared.lock().unwrap();
            match self.role {
                Role::P0 => {
                    st.p0_input = Some(my_sparse.clone());
                    st.p0_result_tx = Some(tx);
                }
                Role::P1 => {
                    st.p1_input = Some(my_sparse.clone());
                    st.p1_result_tx = Some(tx);
                }
            }
            if st.p0_input.is_some() && st.p1_input.is_some() {
                let a = st.p0_input.take().unwrap();
                let b = st.p1_input.take().unwrap();
                let dmpf_seed = st.rng_seed.wrapping_add(st.seq.wrapping_mul(0xDEADBEEF));
                st.seq = st.seq.wrapping_add(1);

                // Compute the cross-product (sparse cyclic mul) and filter non-zeros.
                let dense = sparse_cyclic_mul_dense::<F>(&a, &b);
                let points: Vec<(u64, F)> = dense
                    .into_iter()
                    .enumerate()
                    .filter(|(_, v)| !v.is_zero())
                    .map(|(i, v)| (i as u64, v))
                    .collect();

                // Trusted-dealer DMPF gen (the mock part: in reality this would be
                // a 2-party interactive protocol that doesn't reveal either side's
                // input to a dealer).
                let (k0, k1) = gen_dmpf::<F>(log_n, &points, dmpf_seed);

                let tx0 = st.p0_result_tx.take().unwrap();
                let tx1 = st.p1_result_tx.take().unwrap();
                tx0.send(k0).ok();
                tx1.send(k1).ok();
            }
        }
        let key = rx
            .recv()
            .map_err(|e| eyre::eyre!("mock dmpf gen: channel error: {e}"))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmpf::eval_all as dmpf_eval_all;
    use crate::ring_lpn::sparse_cyclic_mul_dense;
    use ark_bn254::Fr;
    use rand::SeedableRng;

    #[test]
    fn mock_dmpf_gen_produces_correct_cross_product() {
        let (mut p0, mut p1) = MockDmpfGenProtocol::<Fr>::new_pair(42);

        let log_n = 10;
        let n = 1usize << log_n;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let sp0 = SparsePoly::<Fr>::random(n, 8, &mut rng);
        let sp1 = SparsePoly::<Fr>::random(n, 8, &mut rng);

        let expected = sparse_cyclic_mul_dense::<Fr>(&sp0, &sp1);

        let sp0_clone = sp0.clone();
        let sp1_clone = sp1.clone();
        let h0 = std::thread::spawn(move || p0.gen_dmpf_share(&sp0_clone, log_n).unwrap());
        let h1 = std::thread::spawn(move || p1.gen_dmpf_share(&sp1_clone, log_n).unwrap());

        let k0 = h0.join().unwrap();
        let k1 = h1.join().unwrap();

        let v0 = dmpf_eval_all(&k0);
        let v1 = dmpf_eval_all(&k1);
        for i in 0..n {
            assert_eq!(v0[i] + v1[i], expected[i], "position {i}");
        }
    }
}
