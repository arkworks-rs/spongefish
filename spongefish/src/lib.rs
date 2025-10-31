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
pub mod domain_separator;

// Re-export the core interfaces for building the FS transformation.
pub use codecs::{Codec, Decoding, Encoding};
pub use domain_separator::DomainSeparator;
pub use duplex_sponge::{DuplexSponge, DuplexSpongeInterface, Unit};
pub use error::{VerificationError, VerificationResult};
pub use io::{NargDeserialize, NargSerialize};
pub use narg::{ProverState, VerifierState};
#[cfg(feature = "derive")]
pub use spongefish_derive::{Decoding, Encoding, NargDeserialize, Unit};

/// The default hash function provided by the library.
#[cfg(feature = "sha3")]
pub type StdHash = instantiations::Shake128;

#[macro_export]
macro_rules! protocol_id {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::domain_separator::protocol_id(core::format_args!($fmt $(, $arg)*))
    }};
}

#[macro_export]
macro_rules! session_id {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::domain_separator::session_id(core::format_args!($fmt $(, $arg)*))
    }};
}

#[cfg(all(not(feature = "sha3"), feature = "blake3"))]
pub type DefaultHash = instantiations::Shake128;

// /// Unit-tests.
// #[cfg(test)]
// mod tests;
