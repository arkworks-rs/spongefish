//! # Duplex Sponge Fiat-Shamir
//!
//! Spongefish implements the duplex-sponge Fiat–Shamir transformation for
//! public-coin interactive arguments. This crate is spec-compatible with
//! [draft-irtf-cfrg-fiat-shamir], and the generic duplex construction follows
//! [[CO25]].
//!
//! The main feature of this library is to let users write an interactive
//! [`Argument`] and automatically compile it into a NARG that can be generated
//! with [`Narg::prove`] and verified with [`Narg::verify`].
//!
//! It also offers a "transcript-like" API via [`ProverState`] or [`VerifierState`] directly.
//!
//! ## Usage
//!
//! A minimal (cryptographically unsound) example is:
//!
//! ```
//! # #[cfg(all(feature = "turboshake128", feature = "getrandom"))]
//! # {
//! use spongefish::{Argument, Narg, Transcript, VerificationError, Witness};
//!
//! struct Equality;
//!
//! impl Argument for Equality {
//!     type Instance = u32;
//!     type Witness = u32;
//!     type Output = ();
//!
//!     fn run<T: Transcript>(
//!         transcript: &mut T,
//!         instance: &u32,
//!         witness: Witness<&u32>,
//!     ) -> Result<(), VerificationError> {
//!         let value = transcript.prover_message(witness.map(|value| *value))?;
//!         transcript.check(|| value == *instance)
//!     }
//! }
//!
//! let tag = b"spongefish/docs/equality/v1";
//! let (narg, ()) = Narg::prove::<Equality>(tag, &7, &7).unwrap();
//! Narg::verify::<Equality>(tag, &7, &narg).unwrap();
//! # }
//! ```
//!
//! See the [README quick start] for a multi-round example.
//!
//! ## Security requirements
//!
//! Spongefish implements a transformation; it does not make an insecure
//! interactive protocol secure. The interactive protocol must be public coin, and
//! implementors must follow the security considerations of
//! [draft-irtf-cfrg-fiat-shamir]. In particular:
//!
//! - Every application tag must uniquely pin the **non-interactive** NARG, its
//!   codecs, and the application context where it is being used. Reusing a tag
//!   can invalidate soundness and domain separation.
//!   [`Narg`] derives the typed [`SessionId`] from this tag.
//! - Encodings absorbed into the random oracle must satisfy the
//!   prefix-freeness requirements documented by [`Encoding`]. Codec changes
//!   require a new application tag.
//! - Verification must consume the complete NARG. [`Narg::verify`] performs
//!   this check; low-level users must call [`VerifierState::check_eof`].
//! - Prover randomness must be secret, unpredictable, and never reused.
//!   Deterministic constructors are for tests and test vectors only.
//!
//! The current codebase should be treated as unaudited. Earlier revisions were
//! reviewed by Radically Open Security and OpenZeppelin; see the repository's
//! [security policy] for scope, versions, and private reporting instructions.
//!
//! ## Messages and codecs
//!
//! Conversions to/from the hash function are handled by the traits:
//!
//! - [`Encoding`], which is a prefix-free serialization map.
//!   [`Encoding<[u8]>`] is used for serialization as well.
//! - [`Decoding`], which is a uniform-distribution-preserving map.
//!
//! To deserialize objects from the NARG string, use [`NargDeserialize`].
//! [`Codec`] is the combined shorthand, and the optional `derive` feature supplies derive
//! macros for these traits.
//!
//! Fixed-width integers, byte arrays, and tuples have built-in codecs.
//! Variable-length sequences must use [`LengthPrefixed`] (or an equally
//! unambiguous custom encoding); concatenating variable-length encodings
//! without framing is unsafe.
//!
//! For a sponge over another alphabet `U`, [`Encoding<[U]>`] is the map
//! absorbed into the oracle, while [`Encoding`] remains the byte serialization
//! written to the NARG. The low-level
//! [`ProverState::prover_message_with`] and
//! [`VerifierState::prover_message_with`] methods accept these maps as
//! closures when implementing traits is inconvenient.
//!
//! ## Prover randomness
//!
//! With the default `getrandom` feature, the NARG prover will also have access to a
//! cryptographically secure pseudorandom number generator ([`PrivateRng`])
//! seeded by the operating system.
//!
//! [`ProverState::mix_entropy`] can mix an additional fixed-width seed.
//! [`ProverState::new_with_seed`] is deterministic and must
//! not be used for production proofs.
//!
//! ## Suites and low-level APIs
//!
//! The [`instantiations`] module provides:
//!
//! - `Shake128` and `TurboShake128`, the suites specified by
//!   [draft-irtf-cfrg-fiat-shamir]. `TurboShake128` is [`DefaultHash`] and backs
//!   [`Narg`] when the default `turboshake128` feature is enabled.
//! - `Keccak` and `Ascon12`, overwrite-mode duplex sponges available through
//!   their respective feature flags. These are not the draft's SHAKE suites.
//! - [`instantiations::XOF`] and [`instantiations::Hash`], bridges for the
//!   RustCrypto `digest` traits. Constructions outside the draft or the ideal-
//!   permutation analysis of [[CO25]] should be treated as heuristic.
//!
//! [`FiatShamir`] selects a non-default sponge. [`DuplexSponge`] and
//! [`DuplexSpongeInterface`] expose the underlying construction for specialist
//! use. The `yolocrypto` feature exposes additional internal state and should
//! not be enabled by ordinary applications.
//!
//! This crate is `no_std`.
//!
//! [README quick start]: https://github.com/arkworks-rs/spongefish#example
//! [security policy]: https://github.com/arkworks-rs/spongefish/blob/main/SECURITY.md
//! [CO25]: https://eprint.iacr.org/2025/536.pdf
//! [draft-irtf-cfrg-fiat-shamir]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

// Keep the README's canonical quick start compiled without duplicating it in
// the rendered crate documentation.
#[cfg(all(doctest, feature = "turboshake128", feature = "getrandom"))]
#[doc = include_str!("../../README.md")]
pub mod readme_doctests {}

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
pub use error::VerificationError;
pub use narg_prover::ProverState;
pub use narg_string::{NargDeserialize, NargReader};
pub use narg_verifier::VerifierState;
pub use private_rng::PrivateRng;
#[cfg(feature = "derive")]
pub use spongefish_derive::{Codec, Decoding, Encoding, NargDeserialize, Unit};

/// The default hash function provided by the library: the TurboSHAKE128
/// duplex sponge of draft-irtf-cfrg-fiat-shamir.
#[cfg(feature = "turboshake128")]
pub type DefaultHash = instantiations::TurboShake128;

/// The 32-byte session identifier of draft-irtf-cfrg-fiat-shamir, as produced
/// by [`derive_session_id`] from an application tag.
///
/// It is a newtype rather than a bare `[u8; 32]` so that a tag and an
/// identifier cannot be confused for one another: a 32-byte tag literal is
/// itself a `&[u8; 32]`, and would otherwise seed a transcript directly
/// wherever an identifier is expected — silently skipping the derivation.
///
/// ```
/// # #[cfg(feature = "turboshake128")]
/// # {
/// use spongefish::Narg;
///
/// let session_id = Narg::derive_session_id(b"example-v00");
/// assert_eq!(session_id.as_bytes().len(), 32);
/// # }
/// ```
///
/// Transcript constructors accept only `&SessionId`, so passing either a tag
/// or the identifier's raw bytes does not compile:
///
/// ```compile_fail,E0308
/// use spongefish::{Narg, ProverState};
///
/// let session_id = Narg::derive_session_id(b"example-v00");
/// ProverState::new(session_id.as_bytes(), b"instance");
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
/// let session_id = spongefish::derive_session_id::<spongefish::DefaultHash>(b"EXAMPLE-V01-DSFS");
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
