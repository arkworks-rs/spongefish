//!
//! **This crate is work in progress, not suitable for production.**
//!
//! spongefish helps performing Fiat-Shamir on any public-coin protocol.
//! It enables secure provision of randomness for the prover and secure generation
//! of random coins for the verifier.
//! It is inspired by the [SAFE] API, with minor variations.
//!
//!
//! # Overview
//!
//! The library does two things:
//!
//! - Assist in the construction of a protocol transcript for a public-coin zero-knowledge proof ([`ProverState`]),
//! - Assist in the deserialization and verification of a public-coin protocol ([`VerifierState`]).
//!
//! The basic idea behind spongefish is that prover and verifier "commit" to the protocol before running the actual protocol.
//! A string encoding the sequence of messages sent from the prover and the verifier (the [`DomainSeparator`]) is used to generate an  "IV" that initialises the duplex sponge interface.
//!
//! The prover just proceeds with concatenation, without ever worrying
//! about encoding length and special flags to embed in the hash function.
//! This allows for
//! better preprocessing,
//! friendliness with algebraic hashes,
//! static composition of protocol (and prevention of composition during the execution of a protocol),
//! and inspection of the Fiat-Shamir transformation.
//!
//! ```
//! use spongefish::{DomainSeparator, DefaultHash};
//!
//! let domain_separator = DomainSeparator::<DefaultHash>::new("👩‍💻🥷🏻👨‍💻 building 🔐🔒🗝️")
//!         // this indicates the prover is sending 10 elements (bytes)
//!         .absorb(10, "first")
//!         // this indicates the verifier is sending 10 elements (bytes)
//!         .squeeze(10, "second");
//! assert_eq!(domain_separator.as_bytes(), "👩‍💻🥷🏻👨‍💻 building 🔐🔒🗝️\0A10first\0S10second".as_bytes())
//! ```
//! An [`DomainSeparator`] is a UTF8-encoded string wrapper. Absorptions are marked by `A` and
//! squeezes by `S`, followed by the respective length
//! (note: length is expressed in terms of [`Unit`], native elements over which the hash function works).
//! A label is added at the end of each absorb/squeeze, to describe the *type* and
//! *the variable* as used in the protocol. Operations are separated by a NULL byte and therefore labels cannot contain
//! NULL bytes themselves, nor they can start with an ASCII digit.
//!
//! # Batteries included
//! The library comes with support for algebraic objects over arkworks and zkcrypto:
//! - with feature flag `--feature=ark`, the module [`codecs::arkworks_algebra`] provides extension traits for arkworks fields and groups;
//! - with feature flag `--feature=group`, the module [`codecs::zkcrypto_group`] provides extension traits for zkcrypto's field and group traits.
//! See the [`codecs`] module for more information.
//!
//!
//! # Non-interactive arguments (NARGs) strings
//!
//! Prover and verifier argument strings are built respectively with [`ProverState`] and [`VerifierState`].
//! [`ProverState`] is meant to be **private** and also holds the prover's random coins, while [`VerifierState`] provides the **public coins** of the protocol.
//! Given the `DomainSeparator``, it is possible to build a [`ProverState`] instance that can
//! build the protocol transcript, and seed the private randomness for the prover.
//!
//! ```
//! use spongefish::*;
//! use rand::Rng;
//!
//! // Create a new protocol that will absorb 1 byte and squeeze 16 bytes.
//! let domain_separator = DomainSeparator::<DefaultHash>::new("example-protocol 🤌").absorb(1, "↪️").squeeze(16, "↩️");
//! let mut prover_state = domain_separator.to_prover_state();
//! // The prover sends the byte 0x42.
//! prover_state.add_bytes(&[0x42]).unwrap();
//! // The prover receive a 128-bit challenge.
//! let mut chal = [0u8; 16];
//! prover_state.fill_challenge_bytes(&mut chal).unwrap();
//! // The transcript is recording solely the bytes sent by the prover so far.
//! assert_eq!(prover_state.narg_string(), [0x42]);
//! // Generate some private randomness bound to the protocol transcript.
//! let private = prover_state.rng().gen::<[u8; 2]>();
//!
//! assert_eq!(prover_state.narg_string(), [0x42]);
//! ```
//!
//! (Note: spongefish provides aliases [`DefaultHash`] and [`DefaultRng`] mapping to secure hash functions and random number generators).
//! An [`ProverState`] instance can generate public coins (via a [`StatefulHashObject`] instance) and private coins.
//! Private coins are generated with a sponge that absorbs whatever the public sponge absorbs, and is seeded by a cryptographic random number generator throughout the protocol by the prover.
//! This way, it is really hard to produce two different challenges for the same prover message.
//!
//! The verifier can use a [`VerifierState`] instance to recover the protocol transcript and public coins:
//! ```
//! use spongefish::{DomainSeparator, VerifierState};
//! use spongefish::traits::*;
//! use spongefish::keccak::Keccak;
//! use rand::{Rng, rngs::OsRng};
//!
//! let domain_separator = DomainSeparator::<Keccak>::new("example-protocol 🧀").absorb(1, "in 🍽️").squeeze(16, "out 🤮");
//! let transcript = [0x42];
//! let mut verifier_state = domain_separator.to_verifier_state(&transcript);
//!
//! // Read the first message.
//! let [first_message] = verifier_state.next_bytes().unwrap();
//! assert_eq!(first_message, 0x42);
//!
//! // Squeeze out randomness.
//! let chal = verifier_state.challenge_bytes::<16>().expect("Squeezing 128 bits");
//! ```
//!
//!
//!
//! # Acknowledgements
//!
//! This library is an implementation of
//! "A Fiat–Shamir Transformation From Duplex Sponges",
//! by Alessandro Chiesa and Michele Orrù.
//!
//! Internally it takes inspiration from:
//! - Libsignal's [shosha256], by Trevor Perrin. It provides an absorb/squeeze interface over legacy hash functions.
//! - the [SAFE] API, by Dmitry Khovratovich, JP Aumasson, Porçu Quine, Bart Mennink. To my knowledge they are the first to introduce this idea of using an domain separator to build a transcript and the SAFE API.
//! - [Merlin], by Henry de Valence. To my knowledge it introduced this idea of a `Transcript` object carrying over the state of the hash function throughout the protocol.
//!
//!
//! [shosha256]: https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shosha256.rs
//! [SAFE]: https://eprint.iacr.org/2023/522
//! [Merlin]: https://github.com/dalek-cryptography/merlin
//! [`digest::Digest`]: https://docs.rs/digest/latest/digest/trait.Digest.html

#[cfg(target_endian = "big")]
compile_error!(
    r#"
This crate doesn't support big-endian targets.
"#
);

/// Hash functions traits and implementations.
pub mod duplex_sponge;
/// Built-in proof results.
mod errors;
/// Verifier state and transcript deserialization.
mod verifier;

/// Built-in permutation functions.
pub mod keccak;

/// APIs for common zkp libraries.
pub mod codecs;
/// domain separator
mod domain_separator;
/// Prover's internal state and transcript generation.
mod prover;
/// SAFE API.
mod sho;
/// Unit-tests.
#[cfg(test)]
mod tests;

/// Proposed alternative domain separator
pub mod pattern;

/// Traits for byte support.
pub mod traits;

pub use domain_separator::DomainSeparator;
pub use duplex_sponge::{legacy::DigestBridge, DuplexSpongeInterface, Unit};
pub use errors::{DomainSeparatorMismatch, ProofError, ProofResult};
pub use prover::ProverState;
pub use sho::HashStateWithInstructions;
pub use traits::*;
pub use verifier::VerifierState;

/// Default random number generator used ([`rand::rngs::OsRng`]).
pub type DefaultRng = rand::rngs::OsRng;

/// Default hash function used ([`keccak::Keccak`]).
pub type DefaultHash = keccak::Keccak;
