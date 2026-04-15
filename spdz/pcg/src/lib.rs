//! Pseudorandom Correlation Generator (PCG) for Beaver triples over BN254.
//!
//! MVP implementation following Boyle et al. "Efficient PCGs from Ring-LPN"
//! (CRYPTO 2020). The construction produces OLE correlations:
//!
//!   Sender holds (a, c), Receiver holds (b, d) such that:
//!     c + d = a * b   (additive shares of the product)
//!
//! The PCG compresses this via sparse polynomial representation:
//!   Each party holds a sparse polynomial e_i (random, t-sparse) and a dense
//!   polynomial u_i (pseudorandom from a short seed).
//!   The product polynomial r = u_0 * e_1 + u_1 * e_0 + e_0 * e_1 splits into
//!   additive shares that the parties produce locally.
//!
//! This MVP implementation:
//! - Operates directly on BN254 Fr (no subfield/container tricks)
//! - Uses FFT multiplication via ark-poly (BN254 has 2^28 smooth subgroup)
//! - **Does NOT yet implement the DMPF compression** — both parties are assumed
//!   to know each other's sparse polynomials directly. This is INSECURE but
//!   validates the expansion math. Real DMPF comes in Phase 1c.

pub mod pcg;
pub mod preprocessing;
pub mod sparse;
pub mod triples;

pub use pcg::{PcgParams, PcgSeed, Role};
pub use preprocessing::PcgPreprocessing;
pub use triples::{ole_to_beaver_triples, BeaverTripleShare};

/// Default parameters for BN254: ~1M OLEs with moderate security.
/// These should be reviewed against the LPN security estimator before use.
pub const DEFAULT_LOG_N: usize = 20; // 2^20 ≈ 1M OLEs
pub const DEFAULT_T: usize = 128; // sparsity parameter (non-zero entries)
