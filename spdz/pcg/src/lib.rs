//! SPDZ preprocessing adapter for the standalone `pcg-bn254` crates.
//!
//! This crate is the SPDZ-specific glue that wires the generic
//! [`pcg-core`] and [`pcg-protocols`] primitives into spdz-core's
//! `SpdzPreprocessing` trait. The actual crypto and PCG logic lives in
//! `pcg-bn254` (a separate, reusable repo).
//!
//! [`pcg-core`]: https://github.com/zkfrov/pcg-bn254
//! [`pcg-protocols`]: https://github.com/zkfrov/pcg-bn254

pub mod preprocessing;

#[cfg(feature = "ferret")]
pub mod ferret_protocol;

// Re-export the public PCG API so downstream crates have a single import point.
pub use pcg_core::{
    gen_dmpf, gen_dpf, ole_to_beaver_triples, pcg::Role, BeaverTripleShare, DmpfKey, DpfKey,
    PcgParams, PcgSeed, RingLpnPcgParams, RingLpnPcgSeed, SparsePoly,
};
pub use pcg_protocols::{DmpfGenProtocol, MockDmpfGenProtocol, MockOleProtocol, OleProtocol};
pub use preprocessing::PcgPreprocessing;

#[cfg(feature = "ferret")]
pub use ferret_protocol::FerretOleProtocol;
