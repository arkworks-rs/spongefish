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

pub use codecs::{Decoding, Encoding};
/// Heuristics for building misuse-resistant protocol identifiers.
// mod domain_separator;

// /// Unit-tests.
// #[cfg(test)]
// mod tests;

// Re-export the core interfaces for building the FS transformation.
pub use duplex_sponge::{DuplexSponge, DuplexSpongeInterface, Unit};
pub use error::{VerificationError, VerificationResult};
pub use io::{NargDeserialize, NargSerialize};
pub use narg::{ProverState, VerifierState};
#[cfg(feature = "derive")]
pub use spongefish_derive::{Decoding, Encoding, NargDeserialize, Unit};

/// The default hash function provided by the library.
#[cfg(feature = "sha3")]
pub type StdHash = instantiations::Shake128;

#[cfg(all(not(feature = "sha3"), feature = "blake3"))]
pub type DefaultHash = instantiations::Shake128;

pub trait Codec<T = [u8]>: NargDeserialize + NargSerialize + Encoding<T> + Decoding<T>
where
    T: ?Sized,
{
}
impl<T: ?Sized, E: NargDeserialize + NargSerialize + Encoding<T> + Decoding<T>> Codec<T> for E {}

#[cfg(all(test, feature = "derive"))]
mod unit_derive_tests {
    use super::Unit;

    #[derive(Clone, crate::Unit)]
    struct NamedUnit {
        first: u8,
        second: u8,
    }

    #[derive(Clone, crate::Unit)]
    struct TupleUnit(u8, u8);

    #[derive(Clone, crate::Unit)]
    struct MarkerUnit;

    #[test]
    fn zero_named_fields() {
        let zero = NamedUnit::ZERO;
        assert_eq!(zero.first, 0);
        assert_eq!(zero.second, 0);
    }

    #[test]
    fn zero_tuple_fields() {
        let zero = TupleUnit::ZERO;
        assert_eq!(zero.0, 0);
        assert_eq!(zero.1, 0);
    }

    #[test]
    fn zero_unit_struct() {
        let _ = MarkerUnit::ZERO;
    }
}
