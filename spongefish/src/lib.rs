//! The Fiat-Shamir transformation for public-coin protocols.
//!
//! # Examples
//!
//! The starting point is building a [`DomainSeparator`], from which
//! a [`ProverState`] and [`VerifierState`] can be built.
//! ```
//! use spongefish::domain_separator;
//!
//! // In this example, we prove knowledge of x such that 2^x mod M31 is Y
//! fn language(x: u32) -> u32 { (2u64.pow(x) % ((1 << 31) -1)) as u32 }
//! let witness = 42;
//! let instance = [2, language(witness)];
//!
//! let domsep = domain_separator!("The simplest interactive proof is just sending the witness")
//!             .instance(&instance);
//!
//! // create the prover using the standard construction.
//! let mut prover = domsep.std_prover();
//! prover.prover_message(&witness);
//! let proof = prover.narg_string();
//!
//! // check that the verifier got the actual proof.
//! let mut verifier = domsep.std_verifier(proof);
//! let claimed_witness = verifier.prover_message::<u32>().expect("unable to read a u32");
//! verifier.finish_checking(language(claimed_witness) == language(witness)).expect("verification failure")
//! ```
//!
//! # Supported hash functions
//!
//! All hash functions are available in [`spogefish::instantiations`][instantiations]:
//!
//! 1. [`Keccak`][instantiations::Keccak], the duplex sponge construction [[CO25], Section 3.3] for the
//! [`keccak::f1600`] permutation [Keccak-f].
//! Available with the `keccak` feature flag;
//! 2. [`Ascon12`][instantiations::Ascon12], the duplex sponge construction [[CO25], Section 3.3] for the
//! [`ascon`] permutation [Ascon], used in overwrite mode.
//! Available with the `ascon` feature flag;
//! 3. [`Shake128`][instantiations::Shake128], based on the extensible output function [sha3::Shake128].
//! Available with the `sha3` feature flag (enabled by default);
//! 4. [`Blake3`][instantiations::Blake3], based on the extensible output function [blake3::Hasher].
//! Available with the `sha3` feature flag (enabled by default);
//! 5. [`SHA256`][instantiations::SHA256], based on [`sha2::Sha256`] used as a stateful hash object.
//! Available with the `sha2` feature flag;
//! 6. [`SHA512`][instantiations::SHA512], based on [`sha2::Sha512`] used as a stateful hash object.
//! Available with the `sha2` feature flag.
//!
//! ## Security considerations
//!
//! Only Constructions (1) and (2) are proven secure.
//! All other constructions are built using heuristics.
//!
//! # Implementing your own hash functions
//!
//! The duplex sponge construction [`DuplexSponge`] is described
//! in [[CO25], Section 3.3].
//!
//! The extensible output function [`instantiations::XOF`]
//! wraps an object implementing [`digest::ExtendableOutput`]
//! and implements the duplex sponge interface with little-to-no code.
//! Its implementation has little differences with [`DuplexSponge`].
//!
//! The hash bridge [`Hash`][crate::instantiations::Hash] wraps an object implementing
//! the [`digest::Digest`] trait, and implements the [`DuplexSpongeInterface`]
//!
//! [SHA2]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//! [Keccak-f]: https://keccak.team/keccak_specs_summary.html
//! [Ascon]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.pdf
//! [CO25]: https://eprint.iacr.org/2025/536.pdf

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
pub(crate) mod io;

/// Codecs are functions for encoding prover messages into [`Unit`]s  and producing verifier messages.
pub(crate) mod codecs;

/// Defines [`VerificationError`].
pub(crate) mod error;

/// Heuristics for building misuse-resistant protocol identifiers.
pub mod domain_separator;

// Re-export the core interfaces for building the FS transformation.
pub use codecs::{Codec, Decoding, Encoding};
pub use domain_separator::DomainSeparator;
pub use duplex_sponge::{DuplexSponge, DuplexSpongeInterface, Permutation, Unit};
pub use error::{VerificationError, VerificationResult};
pub use io::{NargDeserialize, NargSerialize};
pub use narg::{ProverState, VerifierState};
#[cfg(feature = "derive")]
pub use spongefish_derive::{Codec, Decoding, Encoding, NargDeserialize, Unit};

/// The default hash function provided by the library.
#[cfg(feature = "sha3")]
pub type StdHash = instantiations::Shake128;

#[macro_export]
macro_rules! domain_separator {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::DomainSeparator::<_, [u8; 64]>::new($crate::domain_separator::protocol_id(core::format_args!($fmt $(, $arg)*)))
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
