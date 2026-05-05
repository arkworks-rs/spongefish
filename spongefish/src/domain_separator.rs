use core::{fmt::Arguments, marker::PhantomData};

use rand::rngs::StdRng;

#[cfg(feature = "sha2")]
use sha2::{Digest, Sha512};

#[cfg(feature = "sha3")]
use crate::VerifierState;
use crate::{DuplexSpongeInterface, Encoding, ProverState, StdHash};

/// Sponge / compilation info for [`domain_separator!`] when no explicit `sponge_info` is supplied.
pub const DOMAIN_SEPARATOR_MACRO_SPONGE_INFO: &[u8] = b"spongefish/domain_separator/macro/v1";

/// Marker structure for domain separators without an associated instance.
///
/// The Fiat--Shamir transformation requires an instance to provide a sound non-interactive proof.
/// This type is used to make sure that the developer does not forget to add it.
///
/// ```compile_fail
/// # // a BAD EXAMPLE of instantiating a domain separator.
/// # // It will fail at compilation time.
/// use spongefish::domain_separator;
///
/// domain_separator!("this will not compile").std_prover();
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
/// Built only via [`DomainSeparator::derive`]: `domsep` is a 64-byte SHA-512 digest over
/// length-prefixed `(protocol_id, sponge_info, session)`, then the instance is absorbed
/// separately (duplex or `StdHash` bootstrap).
#[derive(Debug, Clone, Copy)]
pub struct DomainSeparator<I> {
    /// 64-byte domain tag (SHA-512 over the triple); feeds `StdHash::from_protocol_id` / duplex init.
    pub domsep: [u8; 64],
    instance: I,
}

/// Length-prefixed SHA-512 domain derivation: `LE32(|p|)||p||LE32(|i|)||i||LE32(|s|)||s`.
#[cfg(feature = "sha2")]
#[must_use]
pub fn derive_domain_digest(
    protocol_id: &[u8],
    sponge_info: &[u8],
    session: &[u8],
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for field in [protocol_id, sponge_info, session] {
        hasher.update((field.len() as u32).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Raw UTF-8 / formatted bytes for a protocol label (unpadded), for use with [`DomainSeparator::derive`].
#[must_use]
pub fn protocol_label(args: Arguments) -> alloc::vec::Vec<u8> {
    if let Some(message) = args.as_str() {
        return message.as_bytes().to_vec();
    }
    alloc::fmt::format(args).into_bytes()
}

#[cfg(feature = "sha2")]
impl<I: ?Sized> DomainSeparator<WithoutInstance<I>> {
    /// Domain separation from explicit protocol bytes, compilation/sponge info, and session bytes
    /// (SHA-512 over a length-prefixed injective encoding).
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

#[cfg(feature = "sha2")]
/// Precomputes the `(protocol_id, sponge_info)` prefix of [`derive_domain_digest`] so only the
/// session block is hashed per proof.
pub struct DomainSeparatorPrefix {
    prefix: Sha512,
}

#[cfg(feature = "sha2")]
impl DomainSeparatorPrefix {
    #[must_use]
    pub fn new(protocol_id: &[u8], sponge_info: &[u8]) -> Self {
        let mut prefix = Sha512::new();
        for field in [protocol_id, sponge_info] {
            prefix.update((field.len() as u32).to_le_bytes());
            prefix.update(field);
        }
        Self { prefix }
    }

    /// Finishes with the session field and returns a [`DomainSeparator`] ready for `.instance(...)`.
    #[must_use]
    pub fn with_session<I: ?Sized>(&self, session: &[u8]) -> DomainSeparator<WithoutInstance<I>> {
        let mut hasher = self.prefix.clone();
        hasher.update((session.len() as u32).to_le_bytes());
        hasher.update(session);
        DomainSeparator {
            domsep: hasher.finalize().into(),
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
