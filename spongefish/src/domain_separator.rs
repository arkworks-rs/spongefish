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
/// # // a BAD EXAMPLE of instantiating a domain separator.
/// # // It will fail at compilation time.
/// use spongefish::domain_separator;
///
/// domain_separator!("this will not compile").std_prover();
/// ```
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
pub struct WithInstance<'i, I: ?Sized>(&'i I);

/// Domain separator for a Fiat--Shamir transformation.
pub struct DomainSeparator<I, S = [u8; 64]> {
    /// **what** this interactive protocol is.
    pub protocol: [u8; 64],
    // **where** this interactive protocol is being used.
    pub session: Option<S>,
    /// **how** this interactive protocol is used.
    instance: I,
}

impl<I: ?Sized, S> DomainSeparator<WithoutInstance<I>, S> {
    #[must_use]
    pub const fn new(protocol: [u8; 64]) -> Self {
        Self {
            protocol,
            session: None,
            instance: WithoutInstance::new(),
        }
    }
}

impl<I, S> DomainSeparator<I, S> {
    #[must_use]
    pub fn session(self, value: S) -> Self {
        assert!(self.session.is_none());
        Self {
            instance: self.instance,
            session: Some(value),
            protocol: self.protocol,
        }
    }
}

impl<I: ?Sized, S> DomainSeparator<WithoutInstance<I>, S> {
    pub fn instance(self, value: &I) -> DomainSeparator<WithInstance<'_, I>, S> {
        DomainSeparator {
            protocol: self.protocol,
            session: self.session,
            instance: WithInstance(value),
        }
    }
}

impl<I, S> DomainSeparator<WithInstance<'_, I>, S>
where
    I: Encoding,
    S: Encoding,
{
    #[cfg(feature = "sha3")]
    #[must_use]
    pub fn std_prover(&self) -> ProverState {
        let mut prover_state = ProverState::from(StdHash::from_protocol_id(self.protocol));
        if let Some(session_info) = &self.session {
            prover_state.public_message(session_info);
        }
        prover_state.public_message(self.instance.0);
        prover_state
    }

    #[cfg(feature = "sha3")]
    #[must_use]
    pub fn std_verifier<'ver>(&self, narg_string: &'ver [u8]) -> VerifierState<'ver, StdHash> {
        let mut verifier_state =
            VerifierState::from_parts(StdHash::from_protocol_id(self.protocol), narg_string);
        if let Some(session_info) = &self.session {
            verifier_state.public_message(session_info);
        }
        verifier_state.public_message(self.instance.0);
        verifier_state
    }
}

impl<I, S> DomainSeparator<WithInstance<'_, I>, S> {
    pub fn to_prover<H>(&self, h: H) -> ProverState<H, StdRng>
    where
        H: DuplexSpongeInterface,
        [u8; 64]: Encoding<[H::U]>,
        S: Encoding<[H::U]>,
        I: Encoding<[H::U]>,
    {
        let mut prover_state = ProverState::from(h);
        prover_state.public_message(&self.protocol);
        if let Some(session_info) = &self.session {
            prover_state.public_message(session_info);
        }
        prover_state.public_message(self.instance.0);
        prover_state
    }

    pub fn to_verifier<'ver, H>(&self, h: H, narg_string: &'ver [u8]) -> VerifierState<'ver, H>
    where
        H: DuplexSpongeInterface,
        [u8; 64]: Encoding<[H::U]>,
        S: Encoding<[H::U]>,
        I: Encoding<[H::U]>,
    {
        let mut verifier_state = VerifierState::from_parts(h, narg_string);
        verifier_state.public_message(&self.protocol);
        if let Some(session_info) = &self.session {
            verifier_state.public_message(session_info);
        }
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
