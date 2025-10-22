//!
//! **This crate is work in progress, not suitable for production.**
//!
//! spongefish helps performing Fiat-Shamir on any public-coin protocol.
//! It enables secure provision of randomness for the prover and secure generation
//! of random coins for the verifier.
//! It is inspired by the [SAFE] API, with minor variations.
//!
//! # Overview
//!
//! The library does two things:
//!
//! - Assist in the construction of a protocol transcript for a public-coin zero-knowledge proof ([`ProverState`]),
//! - Assist in the deserialization and verification of a public-coin protocol ([`VerifierState`]).
//!

#![no_std]
// #![feature(generic_const_exprs)]

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
mod io;

/// Codecs are functions for encoding prover messages into [`Unit`]s  and producing verifier messages.
mod codecs;

/// Defines [`VerificationError`].
mod error;

/// Heuristics for building misuse-resistant protocol identifiers.
mod domain_separator;

/// Unit-tests.
#[cfg(test)]
mod tests;

pub use domain_separator::{sho::HashStateWithInstructions, DomainSeparator};
// Re-export the core interfaces for building the FS transformation.
pub use duplex_sponge::{DuplexSponge, DuplexSpongeInterface, Unit};
pub use error::{VerificationError, VerificationResult};
pub use narg::{ProverState, VerifierState};

/// Default random number generator used ([`rand::rngs::OsRng`]).
pub type DefaultRng = rand::rngs::OsRng;

/// The default hash function provided by the library.
pub type DefaultHash = instantiations::Shake128;
