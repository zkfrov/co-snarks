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
pub mod ferret_bit_ot;

#[cfg(feature = "ferret")]
pub mod ferret_protocol;

#[cfg(feature = "gc")]
pub mod dmpf_oblivious;

#[cfg(feature = "gc")]
pub mod mux_network;

#[cfg(feature = "gc")]
pub mod dpf_oblivious;

#[cfg(feature = "gc")]
pub mod prg_2pc;

// Re-export the public PCG API so downstream crates have a single import point.
pub use pcg_core::{
    ole_to_beaver_triples, pcg::Role, BeaverTripleShare, DmpfKey, DpfKey,
    RingLpnPcgParams, SparsePoly,
};
pub use pcg_protocols::{BitOt, MockBitOt, SumOfDpfsKey};
pub use preprocessing::PcgPreprocessing;

#[cfg(feature = "ferret")]
pub use ferret_bit_ot::FerretBitOt;
#[cfg(feature = "ferret")]
pub use ferret_protocol::FerretOleProtocol;

#[cfg(feature = "gc")]
pub use dmpf_oblivious::{dmpf_gen_oblivious, gen_seed_2party_oblivious, Seed2PartyOblivious};
#[cfg(feature = "gc")]
pub use dpf_oblivious::{
    dpf_gen_oblivious, dpf_gen_oblivious_additive_alpha, dpf_gen_oblivious_mult_beta,
};
#[cfg(feature = "gc")]
pub use mux_network::MuxNetwork;
#[cfg(feature = "gc")]
pub use prg_2pc::{PrgShare, Prg2pcSession};
