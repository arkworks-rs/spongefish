//! The Fiat-Shamir transformation for public-coin protocols.
//!
//! Implements the duplex-sponge Fiat-Shamir transformation of
//! [draft-irtf-cfrg-fiat-shamir], from [[CO25]].
//!
//! Write a protocol once as an [`Argument`] generic over [`Transcript`]. The
//! [`Narg`] transformation runs that body as prover or verifier, supplying a
//! known or unknown [`Witness`] respectively. See the
//! [README quick start](https://github.com/arkworks-rs/spongefish#example) for
//! the complete example.
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
//! Previous versions of this library were audited by [Radically Open Security].
//!
//! The user has full responsibility for choosing the session identifier: it
//! must uniquely identify the non-interactive argument, its codecs, and the
//! application context (see the draft's requirements). Deriving it from a tag
//! via [`derive_session_id`] is the recommended way.
//!
//! Unlike merlin, there are no per-message domain-separation labels:
//! the session identifier pins the protocol, its codecs, and the message schedule,
//! so the sequence of absorb and squeeze operations is fixed before the interactive protocol starts.
//! In particular, this Fiat-Shamir transformation will not bake in degree, order, and endianness metadata
//! into every field element that is being sent to the random oracle.
//! While cheap for bytes, this approach will be really expensive under recursion, and does not fully eliminate
//! message confusion. Ultimately, it's the responsibility of the user to make sure two transcripts will never collide.
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
mod narg_prover;

/// The prover's private randomness source.
mod private_rng;

/// The NARG verifier state.
mod narg_verifier;

/// Utilities for serializing prover messages and de-serializing NARG strings.
pub(crate) mod narg_string;

/// Codecs are functions for encoding prover messages into [`Unit`]s and producing verifier messages.
pub(crate) mod codecs;

/// Defines [`VerificationError`].
pub(crate) mod error;

/// Writing a public-coin interactive argument once, and running it as both
/// sides of the Fiat-Shamir transformation.
mod argument;

// Re-export the core interfaces for building the FS transformation.
#[cfg(feature = "turboshake128")]
pub use argument::Narg;
pub use argument::{Argument, FiatShamir, Transcript, Witness};
#[doc(hidden)]
pub use codecs::ByteArray;
pub use codecs::{Codec, Decoding, Encoding, LengthPrefixed};
pub use duplex_sponge::{
    DuplexSponge, DuplexSpongeInit, DuplexSpongeInterface, Permutation, Unit, UnitFromBytes,
};
pub use error::{VerificationError, VerificationResult};
pub use narg_prover::ProverState;
pub use narg_string::{NargDeserialize, NargReader, NargSerialize};
pub use narg_verifier::VerifierState;
pub use private_rng::PrivateRng;
#[cfg(feature = "derive")]
pub use spongefish_derive::{Codec, Decoding, Encoding, NargDeserialize, Unit};

/// The default hash function provided by the library: the TurboSHAKE128
/// duplex sponge of draft-irtf-cfrg-fiat-shamir.
#[cfg(feature = "turboshake128")]
pub type StdHash = instantiations::TurboShake128;

/// The 32-byte session identifier of draft-irtf-cfrg-fiat-shamir, as produced
/// by [`derive_session_id`] from an application tag.
///
/// It is a newtype rather than a bare `[u8; 32]` so that a tag and an
/// identifier cannot be confused for one another: a 32-byte tag literal is
/// itself a `&[u8; 32]`, and would otherwise seed a transcript directly
/// wherever an identifier is expected — silently skipping the derivation.
/// Transcript constructors accept only `&SessionId`, so passing either a tag
/// or the identifier's raw bytes does not compile:
///
/// ```compile_fail,E0308
/// use spongefish::{derive_session_id, ProverState, StdHash};
///
/// let session_id = derive_session_id::<StdHash>(b"example-v00");
/// ProverState::<StdHash>::new(session_id.as_bytes(), b"instance");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Wraps 32 bytes already derived elsewhere — a vendored test vector, or
    /// an identifier carried across a protocol boundary. Deriving from a tag
    /// with [`derive_session_id`] is the ordinary route.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SessionId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

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
pub fn derive_session_id<H: DuplexSpongeInit<U = u8>>(tag: &[u8]) -> SessionId {
    let mut sponge = H::init(b"irtf-cfrg-fiat-shamir/session-id");
    sponge.absorb(tag);
    let mut out = [0u8; 32];
    sponge.squeeze(&mut out);
    SessionId(out)
}

/// Implementation details used by the derive macros. Not public API.
#[doc(hidden)]
pub mod __private {
    pub use alloc::vec::Vec;
}

/// Unit-tests.
#[cfg(all(test, feature = "turboshake128", feature = "getrandom"))]
mod tests;
