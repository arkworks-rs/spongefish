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

/// APIs for common zkp libraries.
pub mod drivers;

/// domain separator
mod domain_separator;

/// Sponge implementations
pub mod instantiations;

/// Hash functions traits and implementations.
pub mod duplex_sponge;

/// Non-interactive argument state (prover and verifier).
mod narg;

/// Serialization utilities
mod io;

/// Codec interfaces
mod codecs;

/// Unit-tests.
#[cfg(test)]
mod tests;

pub use domain_separator::{sho::HashStateWithInstructions, DomainSeparator};
pub use duplex_sponge::{DuplexSpongeInterface, Unit};
pub use instantiations::hash::Hash;
pub use narg::{ProverState, VerifierState};

/// Default random number generator used ([`rand::rngs::OsRng`]).
pub type DefaultRng = rand::rngs::OsRng;

/// The default hash function provided by the library.
pub type DefaultHash = instantiations::Shake128;

/// The [`spongefish`] package has two types of errors:
/// [`DomainSeparatorMismatch`], which is the error exposed in the low-level interface for bytes and native elements,
/// which arises whenever the domain separator specified and the domain separator executed mismatch.
/// [`ProofError`], which is the error exposed to high-level interfaces dealing with structured types and
/// for end-user applications.
/// Three types of errors can happen when dealing with [`ProofError`]:
///
/// - Serialization/Deseralization errors ([`ProofError::SerializationError`]):
///   This includes all potential problems when extracting a particular type from sequences of bytes.
///
/// - Invalid Proof format ([`ProofError::InvalidIO`]):
///   At a higher level, a proof object have to respect the same length and the same types as the protocol description.
///   This error is a wrapper under the [`DomainSeparatorMismatch`] and provides convenient dereference/conversion implementations for
///   moving from/to an [`DomainSeparatorMismatch`].
///
/// - Invalid Proof:
///   An error to signal that the verification equation has failed. Destined for end users.
///
/// A [`core::Result::Result`] wrapper called [`ProofResult`] (having error fixed to [`ProofError`]) is also provided.
use core::fmt::Display;

/// An error happened when creating or verifying a proof.
#[derive(Debug, Clone)]
pub struct VerificationError;

/// The result type when trying to prove or verify a proof using Fiat-Shamir.
pub type VerificationResult<T> = Result<T, VerificationError>;

impl Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Invalid proof")
    }
}

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
impl std::error::Error for VerificationError {}
