//! Utilities for domain separation.
//!
//! A domain separator binds three pieces of public context before protocol messages are
//! exchanged:
//!
//! - a protocol identifier, chosen by the proof system;
//! - sponge / compilation information, chosen by the Fiat--Shamir compiler or helper macro;
//! - a session identifier, chosen by the application using the proof.
//!
//! These three byte strings are length-prefixed, hashed into a 64-byte transcript tag whose
//! first 32 bytes are derived and whose second 32 bytes are zero, and then the public instance is
//! absorbed separately by the prover/verifier state.
//!
//! Domain separators can then be turned into prover and verifier state via
//! [`DomainSeparator::to_prover`] and [`DomainSeparator::to_verifier`]. Shorthands for
//! [`StdHash`] are available via [`DomainSeparator::std_prover`] and
//! [`DomainSeparator::std_verifier`].
//!
//! ```
//! use spongefish::domain_separator;
//!
//! let x = [1u8, 2, 3];
//! let ds1 = domain_separator!("proto"; "sess").instance(&x);
//! let ds2 = domain_separator!("proto"; "sess").instance(&x);
//!
//! assert_eq!(
//!     ds1.std_prover().verifier_message::<u64>(),
//!     ds2.std_prover().verifier_message::<u64>()
//! );
//! ```

use core::{fmt::Arguments, marker::PhantomData};

use rand::rngs::StdRng;

#[cfg(feature = "sha3")]
use crate::VerifierState;
use crate::{DuplexSpongeInterface, Encoding, ProverState, StdHash};

/// Marker structure for domain separators without an associated instance.
///
/// The Fiat--Shamir transformation requires an instance to provide a sound non-interactive proof.
/// This type is used to make sure that the developer does not forget to add it.
///
/// ```compile_fail
/// use spongefish::domain_separator;
///
/// domain_separator!("this will not compile").std_prover();
/// ```
///
/// ```compile_fail
/// use spongefish::DomainSeparator;
///
/// DomainSeparator::derive(b"proto", b"sponge", b"session").std_prover();
/// ```
#[derive(Debug, Clone, Copy)]
pub struct WithoutInstance<I: ?Sized>(PhantomData<I>);

impl<I: ?Sized> WithoutInstance<I> {
    const fn new() -> Self {
        Self(PhantomData)
    }
}

/// Marker structure storing the instance once it has been provided.
///
/// ```no_run
/// use spongefish::domain_separator;
///
/// let _prover = domain_separator!("this will compile")
///     .instance(b"yellowsubmarine")
///     .std_prover();
/// ```
#[derive(Debug, Clone, Copy)]
pub struct WithInstance<'i, I: ?Sized>(&'i I);

/// Domain separator for a Fiat--Shamir transformation.
///
/// `domsep` is the derived 64-byte transcript tag. The instance is stored separately so it can be
/// absorbed by the selected prover/verifier backend after transcript initialization.
#[derive(Debug, Clone, Copy)]
pub struct DomainSeparator<I> {
    /// 64-byte domain tag; the first 32 bytes are derived and the second 32 bytes are zero.
    /// This feeds `StdHash::from_protocol_id` / duplex init.
    pub domsep: [u8; 64],
    instance: I,
}

/// Length-prefixed domain derivation: `LE32(|p|)||p||LE32(|i|)||i||LE32(|s|)||s`.
///
/// The first 32 bytes are squeezed from [`StdHash`]. The second 32 bytes remain zero
/// so the result can still be used with the existing 64-byte protocol tag hooks.
#[cfg(feature = "sha3")]
#[must_use]
pub fn derive_domain_digest(protocol_id: &[u8], sponge_info: &[u8], session: &[u8]) -> [u8; 64] {
    let mut sponge = StdHash::from_protocol_id(pad_identifier(b"fiat-shamir/domain-separator"));
    sponge.absorb(&(protocol_id.len() as u32).to_le_bytes());
    sponge.absorb(protocol_id);
    sponge.absorb(&(sponge_info.len() as u32).to_le_bytes());
    sponge.absorb(sponge_info);
    sponge.absorb(&(session.len() as u32).to_le_bytes());
    sponge.absorb(session);

    let mut domsep = [0u8; 64];
    sponge.squeeze(&mut domsep[..32]);
    domsep
}

/// Raw UTF-8 / formatted bytes for a protocol label (unpadded), for use with [`DomainSeparator::derive`].
#[must_use]
pub fn protocol_label(args: Arguments) -> alloc::vec::Vec<u8> {
    if let Some(message) = args.as_str() {
        return message.as_bytes().to_vec();
    }
    alloc::fmt::format(args).into_bytes()
}

#[cfg(feature = "sha3")]
impl<I: ?Sized> DomainSeparator<WithoutInstance<I>> {
    /// Domain separation from explicit protocol bytes, compilation/sponge info, and session bytes
    /// (the standard sponge over a length-prefixed injective encoding).
    #[must_use]
    pub fn derive(protocol_id: &[u8], sponge_info: &[u8], session: &[u8]) -> Self {
        Self {
            domsep: derive_domain_digest(protocol_id, sponge_info, session),
            instance: WithoutInstance::new(),
        }
    }

    pub fn instance(self, value: &I) -> DomainSeparator<WithInstance<'_, I>> {
        DomainSeparator {
            domsep: self.domsep,
            instance: WithInstance(value),
        }
    }
}

#[cfg(feature = "sha3")]
/// Precomputes the `(protocol_id, sponge_info)` prefix of [`derive_domain_digest`] so only the
/// session block is hashed per proof.
pub struct DomainSeparatorPrefix {
    prefix: StdHash,
}

#[cfg(feature = "sha3")]
impl DomainSeparatorPrefix {
    #[must_use]
    pub fn new(protocol_id: &[u8], sponge_info: &[u8]) -> Self {
        let mut prefix = StdHash::from_protocol_id(pad_identifier(b"fiat-shamir/domain-separator"));
        prefix.absorb(&(protocol_id.len() as u32).to_le_bytes());
        prefix.absorb(protocol_id);
        prefix.absorb(&(sponge_info.len() as u32).to_le_bytes());
        prefix.absorb(sponge_info);
        Self { prefix }
    }

    /// Finishes with the session field and returns a [`DomainSeparator`] ready for `.instance(...)`.
    #[must_use]
    pub fn with_session<I: ?Sized>(&self, session: &[u8]) -> DomainSeparator<WithoutInstance<I>> {
        let mut sponge = self.prefix.clone();
        sponge.absorb(&(session.len() as u32).to_le_bytes());
        sponge.absorb(session);
        let mut domsep = [0u8; 64];
        sponge.squeeze(&mut domsep[..32]);
        DomainSeparator {
            domsep,
            instance: WithoutInstance::new(),
        }
    }
}

impl<I> DomainSeparator<WithInstance<'_, I>>
where
    I: Encoding,
{
    #[cfg(feature = "sha3")]
    #[must_use]
    pub fn std_prover(&self) -> ProverState {
        let mut prover_state = ProverState::from(StdHash::from_protocol_id(self.domsep));
        prover_state.public_message(self.instance.0);
        prover_state
    }

    #[cfg(feature = "sha3")]
    #[must_use]
    pub fn std_verifier<'ver>(&self, narg_string: &'ver [u8]) -> VerifierState<'ver, StdHash> {
        let mut verifier_state =
            VerifierState::from_parts(StdHash::from_protocol_id(self.domsep), narg_string);
        verifier_state.public_message(self.instance.0);
        verifier_state
    }
}

impl<I> DomainSeparator<WithInstance<'_, I>> {
    pub fn to_prover<H>(&self, h: H) -> ProverState<H, StdRng>
    where
        H: DuplexSpongeInterface,
        [u8; 64]: Encoding<[H::U]>,
        I: Encoding<[H::U]>,
    {
        let mut prover_state = ProverState::from(h);
        prover_state.public_message(&self.domsep);
        prover_state.public_message(self.instance.0);
        prover_state
    }

    pub fn to_verifier<'ver, H>(&self, h: H, narg_string: &'ver [u8]) -> VerifierState<'ver, H>
    where
        H: DuplexSpongeInterface,
        [u8; 64]: Encoding<[H::U]>,
        I: Encoding<[H::U]>,
    {
        let mut verifier_state = VerifierState::from_parts(h, narg_string);
        verifier_state.public_message(&self.domsep);
        verifier_state.public_message(self.instance.0);
        verifier_state
    }
}

#[inline]
#[must_use]
pub fn protocol_id(args: Arguments) -> [u8; 64] {
    if let Some(message) = args.as_str() {
        return pad_identifier(message.as_bytes());
    }

    let formatted = alloc::fmt::format(args);
    pad_identifier(formatted.as_bytes())
}

#[inline]
#[must_use]
pub fn session_id(args: Arguments) -> [u8; 64] {
    if let Some(message) = args.as_str() {
        return derive_session_id(message.as_bytes());
    }

    let formatted = alloc::fmt::format(args);
    derive_session_id(formatted.as_bytes())
}

#[inline]
#[doc(hidden)]
#[must_use]
pub fn session_id_from_str<S>(value: &S) -> [u8; 64]
where
    S: AsRef<str> + ?Sized,
{
    derive_session_id(value.as_ref().as_bytes())
}

fn pad_identifier(identifier: &[u8]) -> [u8; 64] {
    assert!(
        identifier.len() <= 64,
        "protocol identifier must fit in 64 bytes"
    );

    let mut protocol_id = [0u8; 64];
    protocol_id[..identifier.len()].copy_from_slice(identifier);
    protocol_id
}

fn derive_session_id(session: &[u8]) -> [u8; 64] {
    let mut sponge = StdHash::from_protocol_id(pad_identifier(b"fiat-shamir/session-id"));
    sponge.absorb(session);

    let mut session_id = [0u8; 64];
    sponge.squeeze(&mut session_id[32..]);
    session_id
}
