//! The Fiat-Shamir for any public-coin protocol.
//!
//! [`spongefish`] assists in the construction of non-interactive arguments using hash functions.
//!
//!
#![no_std]
extern crate alloc;

#[cfg(target_endian = "big")]
compile_error!(
    r#"
This crate doesn't support big-endian targets.
"#
);

/// Definition of the [`DuplexSpongeInterface`] and the [`DuplexSponge`] construction.
pub mod duplex_sponge;

/// Instantiations of the [`DuplexSpongeInterface`].
pub mod instantiations;

/// The NARG prover and the verifier states [`ProverState`] and [`VerifierState`].
mod narg;

/// Trait implementation for common ZKP libraries.
pub mod drivers;

/// Utilities for serializing prover messages and de-serializing NARG strings.
pub mod io;

/// Codecs are functions for encoding prover messages into [`Unit`]s  and producing verifier messages.
pub mod codecs;

/// Defines [`VerificationError`].
mod error;

/// Heuristics for building misuse-resistant protocol identifiers.
// mod domain_separator;

// /// Unit-tests.
// #[cfg(test)]
// mod tests;

// Re-export the core interfaces for building the FS transformation.
pub use duplex_sponge::{DuplexSponge, DuplexSpongeInterface, Unit};
pub use error::{VerificationError, VerificationResult};
pub use narg::{ProverState, VerifierState};


/// The default hash function provided by the library.
#[cfg(feature = "blake3")]
pub type DefaultHash = instantiations::Blake3;

#[cfg(all(not(feature = "blake3"), feature = "sha3"))]
pub type DefaultHash = instantiations::Shake128;
