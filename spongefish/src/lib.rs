//! The Fiat-Shamir transformation for public-coin protocols.
//!
//! Implements the DSFS transformation from [CO25] that are wire-compatible with [draft-irtf-cfrg-fiat-shamir].
//!
//! # Examples
//!
//! A [`ProverState`] and a [`VerifierState`] can be built via a [`DomainSeparator`], which
//! is composed of a protocol identifier, an optional session identifier, and the public instance.
//! The snippets below illustrate three typical situations.
//!
//! ```
//! use spongefish::domain_separator;
//!
//! // In this example, we prove knowledge of x such that 2^x mod M31 is Y
//! const P: u64 = (1 << 31) -1;
//! fn language(x: u32) -> u32 { (2u64.pow(x) % P) as u32 }
//! let witness = 42;
//! let instance = [2, language(witness)];
//!
//! let domsep = domain_separator!("simplest proof system mod {{P}}"; "{{module_path!()}}")
//!              .instance(&instance);
//!
//! // non-interactive prover
//! let mut prover = domsep.std_prover();
//! prover.prover_message(&witness);
//! let proof = prover.narg_string();
//!
//! // non-interactive verifier
//! let mut verifier = domsep.std_verifier(proof);
//! let claimed_witness = verifier.prover_message::<u32>().expect("unable to read a u32");
//! assert_eq!(language(claimed_witness), language(witness));
//! assert!(verifier.check_eof().is_ok()) // the proof has been fully read
//! ```
//!
//! ## Building on external libraries
//!
//! Spongefish only depends on [`digest`] and [`rand`].
//! Support for common SNARK libraries is available optional feature flags.
//! For instance [`KoalaBear`][`p3_koala_bear::KoalaBear`] can be used to build a sumcheck round:
//!
//! ```
//! // Requires the `p3-baby-bear` feature.
//! use p3_koala_bear::KoalaBear;
//! use p3_field::PrimeCharacteristicRing;
//! use spongefish::{VerificationError, VerificationResult};
//!
//! let witness = [KoalaBear::new(5), KoalaBear::new(9)];
//!
//! let domain = spongefish::domain_separator!("sumcheck"; "{{module_path!()}}").instance(&witness);
//! let mut prover = domain.std_prover();
//! let challenge: KoalaBear = prover.verifier_message::<KoalaBear>();
//! let response = witness[0] * challenge + witness[1];
//! prover.prover_message(&response);
//! let narg_string = prover.narg_string();
//!
//! let mut verifier = domain.std_verifier(narg_string);
//! let challenge = verifier.verifier_message::<KoalaBear>();
//! let response = verifier.prover_message::<KoalaBear>().unwrap();
//! assert_eq!(response, witness[0] * challenge + witness[1]);
//! assert!(verifier.check_eof().is_ok())
//! ```
//!
//! ## Deriving your own encoding and decoding
//!
//! A prover message must implement:
//! - [`Encoding<T>`], where `T` is the relative hash domain (by default `[u8]`). The encoding must be injective and prefix-free;
//! - [`NargSerialize`], to serialize the message in a NARG string.
//! - [`NargDeserialize`], to read from a NARG string.
//!
//! A verifier message must implement [`Decoding`] to allow for sampling of uniformly random elements from a hash output.
//!
//!
//! The interface [`Codec`] is a shorthand for all of the above. It is easy to derive these types via derive macros
//! ```ignore
//! use spongefish::{Codec, domain_separator};
//! use curve25519_dalek::RistrettoPoint;
//!
//! #[derive(Clone, Copy, Codec)]
//! struct PublicKey([u8; 32]);
//!
//! let domain = spongefish::domain_separator!("pk demo"; session = "demo session").instance(b"");
//!
//! let pk = PublicKey([42; 32]);
//! let mut prover = domain.std_prover();
//! prover.public_message(&pk);
//! assert_ne!(prover.verifier_message::<[u8; 32]>(), [0; 32]);
//!
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
//! ## Security considerations
//!
//! Only Constructions (1) and (2) are proven secure, in the ideal permutation model;
//! all other constructions are built using heuristics.
//!
//! Previous version of this library were audited by [Radically Open Security].
//!
//! The user has full responsibility in instantiating [`DomainSeparator`] in a secure way,
//! but the library requiring three elements on initialization:
//! - a mandatory 64-bytes protocol identifier, uniquely identifying the non-interactive protocol being built.
//! - a 64-bytes session identifier, corresponding to session and sub-session identifiers in universal composability lingo)
//! - for a mandatory instance
//!
//! The developer is in charge of making sure they are chosen appropriately.
//! In particular, the instance encoding function prefix-free.
//!
//! [SHA2]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//! [Keccak-f]: https://keccak.team/keccak_specs_summary.html
//! [Ascon]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.pdf
//! [CO25]: https://eprint.iacr.org/2025/536.pdf
//! [Radically Open Security]: https://www.radicallyopensecurity.com/
//! [draft-irtf-cfrg-fiat-shamir]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/

#![no_std]
extern crate alloc;

#[cfg(target_endian = "big")]
compile_error!(
    r#"
This crate doesn't support big-endian targets.
"#
);

/// Definition of the [`DuplexSpongeInterface`] and the [`DuplexSponge`] construction.
mod duplex_sponge;

/// Instantiations of the [`DuplexSpongeInterface`].
pub mod instantiations;

/// The NARG prover state.
mod narg_prover;

/// The NARG verifier state.
mod narg_verifier;

/// Trait implementation for common ZKP libraries.
mod drivers;

/// Utilities for serializing prover messages and de-serializing NARG strings.
pub(crate) mod io;

/// Codecs are functions for encoding prover messages into [`Unit`]s  and producing verifier messages.
pub(crate) mod codecs;

/// Defines [`VerificationError`].
pub(crate) mod error;

/// Heuristics for building misuse-resistant protocol identifiers.
mod domain_separator;

// Re-export the core interfaces for building the FS transformation.
#[doc(hidden)]
pub use codecs::ByteArray;
pub use codecs::{Codec, Decoding, Encoding};
pub use domain_separator::DomainSeparator;
#[doc(hidden)]
pub use domain_separator::{protocol_id, session_id};
pub use duplex_sponge::{DuplexSponge, DuplexSpongeInterface, Permutation, Unit};
pub use error::{VerificationError, VerificationResult};
pub use io::{NargDeserialize, NargSerialize};
pub use narg_prover::ProverState;
pub use narg_verifier::VerifierState;
#[cfg(feature = "derive")]
pub use spongefish_derive::{Codec, Decoding, Encoding, NargDeserialize, Unit};

/// The default hash function provided by the library.
#[cfg(feature = "sha3")]
pub type StdHash = instantiations::Shake128;

/// Build a [`DomainSeparator`] from a formatted string.
///
/// ```
/// let domsep = spongefish::domain_separator!("spongefish"; "DomainSeparator")
///     .instance(b"trivial");
/// let _prover = domsep.std_prover();
/// ```
#[macro_export]
macro_rules! domain_separator {
    ($fmt:literal $(, $arg:expr)* $(,)? ; $sess_fmt:literal $(, $sess_arg:expr)* $(,)?) => {{
        $crate::domain_separator!($fmt $(, $arg)*)
            .session($crate::session_id(core::format_args!($sess_fmt $(, $sess_arg)*)))
    }};
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::DomainSeparator::<_, [u8; 64]>::new($crate::protocol_id(core::format_args!($fmt $(, $arg)*)))
    }};
}

/// Attaches a 64-byte session identifier to the domain separator.
///
/// ```
/// # use spongefish::{DomainSeparator, session};
///
/// DomainSeparator::new([0u8; 64])
///     .session(session!("example at L{{line!()}}"))
///     .instance(b"empty");
/// ```
#[macro_export]
macro_rules! session {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::session_id(core::format_args!($fmt $(, $arg)*))
    }};
}

#[cfg(all(not(feature = "sha3"), feature = "blake3"))]
pub type DefaultHash = instantiations::Shake128;

/// Unit-tests.
#[cfg(test)]
mod tests;
