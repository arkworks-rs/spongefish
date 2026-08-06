//! The Fiat--Shamir transformation for public-coin protocols.
//!
//! Implements the duplex-sponge Fiat--Shamir transformation of
//! [draft-irtf-cfrg-fiat-shamir], from [[CO25]].
//!
//! # Examples
//!
//! A [`ProverState`] and a [`VerifierState`] are built from a 32-byte
//! **session identifier** (derived from an application tag, see
//! [`derive_session_id`]) and the encoded **instance**, which must be
//! non-empty.
//!
//! ```
//! # #[cfg(all(feature = "turboshake128", feature = "getrandom"))]
//! # {
//! use spongefish::{ProverState, StdHash, VerifierState};
//!
//! // In this example, we prove knowledge of x such that 2^x mod M31 is Y
//! const P: u64 = (1 << 31) - 1;
//! fn language(x: u32) -> u32 { (2u64.pow(x) % P) as u32 }
//! let witness = 42;
//! let instance = [2, language(witness)];
//!
//! // The tag identifies the protocol, the codecs, and the application context.
//! let session_id =
//!     spongefish::derive_session_id::<StdHash>(b"example-v00/simplest-proof-system-mod-p");
//!
//! // non-interactive prover
//! let mut prover_state = ProverState::<StdHash>::new(&session_id, &instance);
//! prover_state.prover_message(&witness);
//! let narg_string = prover_state.narg_string();
//! assert!(narg_string.len() > 0);
//!
//! // non-interactive verifier
//! let mut verifier_state = VerifierState::<StdHash>::new(&session_id, &instance, narg_string);
//! let claimed_witness = verifier_state.prover_message::<u32>().expect("unable to read a u32");
//! assert_eq!(language(claimed_witness), language(witness));
//! // a proof is malleable if we don't check we read everything
//! assert!(verifier_state.check_eof().is_ok())
//! # }
//! ```
//!
//! ## Prover randomness
//!
//! The prover carries a private RNG ([`ProverState::rng`]), seeded from the
//! operating system's entropy source (`getrandom`, enabled by default).
//! External randomness can be mixed in with [`ProverState::mix_entropy`].
//! Deterministic provers for test vectors can use
//! [`ProverState::new_with_seed`].
//!
//! ## Deriving your own encoding and decoding
//!
//! A prover message must implement:
//! - [`Encoding<T>`], where `T` is the relative hash domain (by default `[u8]`). The encoding must be injective and prefix-free;
//! - [`NargSerialize`], to serialize the message in a NARG string;
//! - [`NargDeserialize`], to read from a NARG string.
//!
//! A verifier message must implement [`Decoding`] to allow for sampling of uniformly random elements from a hash output.
//!
//! For byte-oriented sponges, a prover message's encoded bytes and serialized
//! bytes coincide. For algebraic sponges, encoding maps to the oracle's alphabet (e.g. field elements),
//! while serialization always targets bytes.
//! The interface [`Codec`] is a shorthand for all of the above.
//!
//! Prover and verifier states accept also codec closures. On byte-oriented sponges,
//! [`ProverState::prover_message_as`] and [`VerifierState::prover_message_as`]
//! take a single closure: the absorbed bytes and the NARG bytes coincide by
//! construction. On sponges over any alphabet,
//! [`ProverState::prover_message_with`] and
//! [`VerifierState::prover_message_with`] take the encoding and
//! (de)serialization maps as separate closures, mirroring the trait pair.
//! Unsigned integers and byte arrays have codecs attached to them.
//! Variable-length sequences use the [`LengthPrefixed`] combinator, which
//! prepends a `u32` element count to keep the encoding prefix-free.
//!
//! # Supported hash functions
//!
//! All hash functions are available in [`instantiations`]:
//!
//! 1. `Shake128` and `TurboShake128`, the duplex sponges of
//!    [draft-irtf-cfrg-fiat-shamir], available with the default
//!    `turboshake128` feature flag (the default is [`StdHash`] =
//!    TurboSHAKE128);
//! 2. `Keccak`, the overwrite-mode duplex sponge
//!    construction [[CO25], Section 3.3] over the Keccak-f\[1600\] permutation
//!    (**not** the draft's SHAKE128 suite). Available with the `keccak` feature flag;
//! 3. `Ascon12`, the overwrite-mode duplex sponge over the
//!    Ascon permutation. Available with the `ascon` feature flag.
//!
//! # Implementing your own hash functions
//!
//! The duplex sponge construction [`DuplexSponge`] is described
//! in [[CO25], Section 3.3].
//!
//! The extensible output function [`instantiations::XOF`]
//! wraps an object implementing [`digest::ExtendableOutput`], and the hash
//! bridge [`Hash`][crate::instantiations::Hash] wraps an object implementing
//! the [`digest::Digest`] trait; both implement the [`DuplexSpongeInterface`].
//!
//! ## Security considerations
//!
//! The SHAKE128 and TurboSHAKE128 suites implement [draft-irtf-cfrg-fiat-shamir];
//! the overwrite-mode duplex sponges (`Keccak`, `Ascon12`) are proven secure in
//! the ideal permutation model [[CO25]]; all other constructions are heuristic.
//!
//! Previous version of this library were audited by [Radically Open Security].
//!
//! The user has full responsibility for choosing the session identifier: it
//! must uniquely identify the non-interactive argument, its codecs, and the
//! application context (see the draft's requirements). Deriving it from a tag
//! via [`derive_session_id`] is the recommended way.
//!
//! [SHA2]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//! [Keccak-f]: https://keccak.team/keccak_specs_summary.html
//! [Ascon]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.pdf
//! [CO25]: https://eprint.iacr.org/2025/536.pdf
//! [Radically Open Security]: https://www.radicallyopensecurity.com/
//! [draft-irtf-cfrg-fiat-shamir]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

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
#[cfg(feature = "turboshake128")]
mod narg_prover;

/// The prover's private randomness source.
#[cfg(feature = "turboshake128")]
mod private_rng;

/// The NARG verifier state.
mod narg_verifier;

/// Utilities for serializing prover messages and de-serializing NARG strings.
pub(crate) mod narg_string;

/// Codecs are functions for encoding prover messages into [`Unit`]s  and producing verifier messages.
pub(crate) mod codecs;

/// Defines [`VerificationError`].
pub(crate) mod error;

// Re-export the core interfaces for building the FS transformation.
#[doc(hidden)]
pub use codecs::ByteArray;
pub use codecs::{Codec, Decoding, Encoding, LengthPrefixed};
pub use duplex_sponge::{DuplexSponge, DuplexSpongeInit, DuplexSpongeInterface, Permutation, Unit};
pub use error::{VerificationError, VerificationResult};
#[cfg(feature = "turboshake128")]
pub use narg_prover::ProverState;
pub use narg_string::{NargDeserialize, NargSerialize};
pub use narg_verifier::VerifierState;
#[cfg(feature = "turboshake128")]
pub use private_rng::PrivateRng;
#[cfg(feature = "derive")]
pub use spongefish_derive::{Codec, Decoding, Encoding, NargDeserialize, Unit};

/// The default hash function provided by the library: the TurboSHAKE128
/// duplex sponge of draft-irtf-cfrg-fiat-shamir.
#[cfg(feature = "turboshake128")]
pub type StdHash = instantiations::TurboShake128;

/// The draft's `DeriveSessionID(tag)`: derive a 32-byte session identifier
/// from an application-chosen tag, using the duplex sponge `H`.
///
/// This is `Init("irtf-cfrg-fiat-shamir/session-id"); Absorb(tag);
/// Squeeze(32)`. Instantiated with the draft suites it matches the draft's
/// construction exactly; other duplex sponges seed through their own
/// [`DuplexSpongeInit`] convention.
///
/// ```
/// # #[cfg(feature = "turboshake128")]
/// # {
/// let session_id = spongefish::derive_session_id::<spongefish::StdHash>(b"EXAMPLE-V01-DSFS");
/// # }
/// ```
#[must_use]
pub fn derive_session_id<H: DuplexSpongeInit>(tag: &[u8]) -> [u8; 32] {
    let mut sponge = H::init(b"irtf-cfrg-fiat-shamir/session-id");
    sponge.absorb(tag);
    let mut out = [0u8; 32];
    sponge.squeeze(&mut out);
    out
}

/// Implementation details used by the derive macros. Not public API.
#[doc(hidden)]
pub mod __private {
    pub use alloc::vec::Vec;
}

/// Unit-tests.
#[cfg(all(test, feature = "turboshake128", feature = "getrandom"))]
mod tests;
