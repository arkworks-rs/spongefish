//! The Fiat-Shamir transformation for public-coin protocols.
//!
//! # Examples
//!
//! The first step in every transcript is building a [`DomainSeparator`], which binds a protocol
//! identifier, an optional session identifier, and the public instance. From there we derive a
//! [`ProverState`] and a [`VerifierState`]. The snippets below illustrate three typical situations.
//!
//! ## 1. Absorbing and squeezing simple integers
//!
//! ```no_run
//! use spongefish::VerificationResult;
//!
//! fn integer_round_trip(secret: u32) -> VerificationResult<()> {
//!     // Everything that is absorbed becomes part of the proof transcript.
//!     let domain = spongefish::domain_separator!("integer demo").instance(&secret);
//!     let mut prover = domain.std_prover();
//!     // Commit to the witness and derive a random challenge from the transcript.
//!     prover.prover_message(&secret);
//!     let challenge: u32 = prover.verifier_message();
//!     let response = secret.wrapping_add(challenge);
//!     prover.prover_message(&response);
//!     let proof = prover.narg_string();
//!
//!     // The verifier replays the same transcript and checks the relation.
//!     let mut verifier = domain.std_verifier(proof);
//!     let witness = verifier.prover_message::<u32>()?;
//!     let challenge = verifier.verifier_message::<u32>();
//!     let response = verifier.prover_message::<u32>()?;
//!     verifier.finish_checking(response == witness.wrapping_add(challenge))
//! }
//! ```
//!
//! ## 2. Using field elements via feature flags (single-round sumcheck)
//!
//! When the `p3-baby-bear` feature is enabled, [`BabyBear`][p3_baby_bear::BabyBear] implements the
//! [`Encoding`] and [`Decoding`] traits through the Plonky3 drivers. The following snippet sketches
//! a single round of sumcheck where the prover commits to a vector `(a, b)`, receives a challenge
//! `c`, and responds with `a * c + b`.
//!
//! ```ignore
//! # // Requires the `p3-baby-bear` feature.
//! # use p3_baby_bear::BabyBear;
//! # use spongefish::VerificationResult;
//!
//! fn single_round_sumcheck() -> VerificationResult<()> {
//!     let witness = [
//!         BabyBear::from_canonical_u32(5),
//!         BabyBear::from_canonical_u32(9),
//!     ];
//!     let domain = spongefish::domain_separator!("sumcheck")
//!         .session(spongefish::session_id!("round 1"))
//!         .instance(&witness);
//!     let mut prover = domain.std_prover();
//!     prover.prover_message(&witness); // commitment to (a, b)
//!     let challenge: BabyBear = prover.verifier_message();
//!     let response = witness[0] * challenge + witness[1];
//!     prover.prover_message(&response);
//!     let proof = prover.narg_string();
//!
//!     let mut verifier = domain.std_verifier(proof);
//!     let committed = verifier.prover_messages::<BabyBear, 2>()?;
//!     let challenge = verifier.verifier_message::<BabyBear>();
//!     let response = verifier.prover_message::<BabyBear>()?;
//!     verifier.finish_checking(response == committed[0] * challenge + committed[1])
//! }
//! ```
//!
//! ## 3. Public keys as prover metadata
//!
//! You can wrap any byte representation inside your own type and implement [`Encoding`] to make it
//! transcript-friendly. Below we model a public key as the digest of a verification key and inject
//! it into both the domain separator and the public transcript.
//!
//! ```no_run
//! use spongefish::{Encoding, VerificationResult};
//!
//! #[derive(Clone, Copy)]
//! struct PublicKey([u8; 32]);
//!
//! impl Encoding<[u8]> for PublicKey {
//!     fn encode(&self) -> impl AsRef<[u8]> {
//!         self.0
//!     }
//! }
//!
//! fn prove_with_public_key(pk: PublicKey) -> VerificationResult<()> {
//!     let domain = spongefish::domain_separator!("pk demo")
//!         .session(spongefish::session_id!("demo session"))
//!         .instance(&pk);
//!     let mut prover = domain.std_prover();
//!     // Public messages are absorbed verbatim and become part of the hash transcript.
//!     prover.public_message(&pk);
//!     let attestation: u32 = 42;
//!     prover.prover_message(&attestation);
//!     let proof = prover.narg_string();
//!
//!     let mut verifier = domain.std_verifier(proof);
//!     verifier.public_message(&pk);
//!     let value = verifier.prover_message::<u32>()?;
//!     verifier.finish_checking(value == 42)
//! }
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

/// The NARG prover and verifier components.
mod narg_prover;
mod narg_verifier;

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
pub use narg_prover::ProverState;
pub use narg_verifier::VerifierState;
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
