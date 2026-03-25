//! The Fiat--Shamir transformation for public-coin protocols.
//!
//! Implements the DSFS transformation from [[CO25]], wire-compatible with [draft-irtf-cfrg-fiat-shamir].
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
//! const P: u64 = (1 << 31) - 1;
//! fn language(x: u32) -> u32 { (2u64.pow(x) % P) as u32 }
//! let witness = 42;
//! let instance = [2, language(witness)];
//!
//! let domsep = domain_separator!("simplest proof system mod {{P}}"; "{{module_path!()}}")
//!              .instance(&instance);
//!
//! // non-interactive prover
//! let mut prover_state = domsep.std_prover();
//! prover_state.prover_message(&witness);
//! let nizk = prover_state.narg_string();
//! assert!(nizk.len() > 0);
//!
//! // non-interactive verifier
//! let mut verifier_state = domsep.std_verifier(nizk);
//! let claimed_witness = verifier_state.prover_message::<u32>().expect("unable to read a u32");
//! assert_eq!(language(claimed_witness), language(witness));
//! // a proof is malleable if we don't check we read everything
//! assert!(verifier_state.check_eof().is_ok())
//! ```
//!
//! The above code will fail to compile if no instance is given.
//! The implementor has full responsibility in providing the correct instance of the proof system.
//!
//! ## Building on external libraries
//!
//! Spongefish only depends on [`digest`] and [`rand`].
//! Support for common SNARK libraries is available optional feature flags.
//! For instance  `p3-koala-bear` provides allows to encode/decode [`p3_koala_bear::KoalaBear`]
//! field elements, and can be used to build a sumcheck round. For other algebraic types, see below.
//! ```
//! # #[cfg(feature = "p3-koala-bear")]
//! # {
//! // Requires the `p3-baby-bear` feature.
//! use p3_koala_bear::KoalaBear;
//! use p3_field::PrimeCharacteristicRing;
//! use spongefish::{VerificationError, VerificationResult};
//!
//! let witness = [KoalaBear::new(5), KoalaBear::new(9)];
//!
//! let domain = spongefish::domain_separator!("sumcheck"; "{{module_path!()}}").instance(&witness);
//! let mut prover = domain.std_prover();
//! let challenge = prover.verifier_message::<KoalaBear>();
//! let response = witness[0] * challenge + witness[1];
//! prover.prover_message(&response);
//! let narg_string = prover.narg_string();
//!
//! let mut verifier = domain.std_verifier(narg_string);
//! let challenge = verifier.verifier_message::<KoalaBear>();
//! let response = verifier.prover_message::<KoalaBear>().unwrap();
//! assert_eq!(response, witness[0] * challenge + witness[1]);
//! // a proof is malleable if we don't check we read everything
//! assert!(verifier.check_eof().is_ok())
//! # }
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
//! The interface [`Codec`] is a shorthand for all of the above.
//! ```
//! # #[cfg(all(feature = "derive", feature = "curve25519-dalek"))]
//! # {
//! // Requires the `derive` and `curve25519-dalek` features.
//! use spongefish::{Codec, domain_separator};
//! use curve25519_dalek::{RistrettoPoint, Scalar};
//!
//! #[derive(Clone, Copy, Codec)]
//! struct PublicKey(RistrettoPoint);
//!
//! let generator = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
//! let domain = spongefish::domain_separator!("challenge-response"; "example")
//!              .instance(&generator);
//!
//! let pk = PublicKey(generator * Scalar::from(42u64));
//! let mut prover = domain.std_prover();
//! prover.public_message(&pk);
//! assert_ne!(prover.verifier_message::<[u8; 32]>(), [0; 32]);
//!
//! # }
//! ```
//! # Supported types
//!
//! Unsigned integers and byte arrays have codecs attached to them.
//! Popular algebraic types are also implemented:
//!
//! 1. arkworks field elements (including `Fp` and extension `Fp2`, `Fp3`, `Fp4`, `Fp6`, `Fp12`)
//! are available via the `ark-ff` feature flag;
//! 2. arkworks elliptic curve elements are available via the `ark-ec` feature flag;
//! 3. Ristretto points of curve25519_dalek are available via the `curve25519-dalek` feature flag;
//! 4. Plonky3's `BabyBear`, `KoalaBear`, and `Mersenne31` field elements
//! are available via (respectively) `p3-baby-bear`, `p3-koala-bear`, `p3-mersenne-31` feature flags.
//! 3. p256 field and elliptic curve elements are available via the `p256` feature flag.
//!
//!
//! # Supported hash functions
//!
//! All hash functions are available in [`instantiations`]:
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
//! - a mandatory 64-bytes protocol identifier,
//!   uniquely identifying the non-interactive protocol being built.
//! - a 64-bytes session identifier,
//!   corresponding to session and sub-session identifiers in universal composability lingo.
//! - a mandatory instance that will be used in the proof system.
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
pub use domain_separator::{protocol_id, session_id, session_id_from_str};
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
    ($fmt:literal $(, $arg:expr)* $(,)? ; $session:expr $(,)?) => {{
        $crate::domain_separator!($fmt $(, $arg)*)
            .session($crate::session_id_from_str(&$session))
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
