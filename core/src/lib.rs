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

/// Hash functions traits and implementations.
pub mod duplex_sponge;

/// Built-in proof results.
mod errors;

/// Verifier state and transcript deserialization.
mod verifier;

/// Built-in permutation functions.
pub mod keccak;

/// APIs for common zkp libraries.
pub mod backend;

/// domain separator
mod domain_separator;

/// Prover's internal state and transcript generation.
mod prover;

/// Serialization utilities
mod io;

/// Codec interfaces
mod codecs;

/// Unit-tests.
#[cfg(test)]
mod tests;


pub use domain_separator::DomainSeparator;
pub use duplex_sponge::{legacy::DigestBridge, DuplexSpongeInterface, Unit};
pub use errors::{DomainSeparatorMismatch, ProofError, ProofResult};
pub use prover::ProverState;
pub use domain_separator::sho::HashStateWithInstructions;
pub use verifier::VerifierState;

/// Default random number generator used ([`rand::rngs::OsRng`]).
pub type DefaultRng = rand::rngs::OsRng;

/// Default hash function used ([`keccak::Keccak`]).
pub type DefaultHash = keccak::Keccak;
