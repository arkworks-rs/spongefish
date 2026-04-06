use core::{fmt, fmt::Arguments, marker::PhantomData};

use rand::rngs::StdRng;

#[cfg(feature = "sha3")]
use crate::VerifierState;
use crate::{DuplexSpongeInterface, Encoding, ProverState, StdHash, Unit};

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
/// DomainSeparator::new([0u8; 64]).instance(b"missing session");
/// ```
pub struct WithoutInstance<I: ?Sized>(PhantomData<I>);

impl<I: ?Sized> WithoutInstance<I> {
    const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<I: ?Sized> fmt::Debug for WithoutInstance<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WithoutInstance")
    }
}

/// Marker structure storing the instance once it has been provided.
///
/// ```no_run
/// use spongefish::domain_separator;
///
/// let _prover = domain_separator!("this will compile")
///     .session(spongefish::session!("example"))
///     .instance(b"yellowsubmarine")
///     .std_prover();
/// ```
pub struct WithInstance<'i, I: ?Sized>(&'i I);

/// Session state marker: no session context has been resolved yet.
#[derive(Debug, Clone, Copy, Default)]
pub struct WithoutSession;

/// Session state marker: a session context has been bound.
pub struct WithSession<S>(pub(crate) S);

impl<S> WithSession<S> {
    /// The session value.
    #[must_use]
    pub const fn value(&self) -> &S {
        &self.0
    }
}

impl<S: fmt::Debug> fmt::Debug for WithSession<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WithSession").field(&self.0).finish()
    }
}

/// Explicit opt-out session marker.
///
/// Used by [`DomainSeparator::without_session`]. Encodes to an empty slice,
/// matching the original behaviour when no session was provided.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSession;

impl<T: Unit> Encoding<[T]> for NoSession {
    fn encode(&self) -> impl AsRef<[T]> {
        let empty: [T; 0] = [];
        empty
    }
}

/// Domain separator for a Fiat--Shamir transformation.
///
/// The API enforces: `new → session | without_session → instance → prover/verifier`.
pub struct DomainSeparator<I, S = WithoutSession> {
    /// **what** this interactive protocol is.
    pub protocol: [u8; 64],
    /// **where** this interactive protocol is being used.
    pub session: S,
    /// **how** this interactive protocol is used.
    instance: I,
}

impl<I: ?Sized> DomainSeparator<WithoutInstance<I>, WithoutSession> {
    #[must_use]
    pub const fn new(protocol: [u8; 64]) -> Self {
        Self {
            protocol,
            session: WithoutSession,
            instance: WithoutInstance::new(),
        }
    }
}

impl<I> DomainSeparator<I, WithoutSession> {
    /// Binds a session context to the transcript.
    #[must_use]
    pub fn session<S>(self, value: S) -> DomainSeparator<I, WithSession<S>> {
        DomainSeparator {
            protocol: self.protocol,
            session: WithSession(value),
            instance: self.instance,
        }
    }

    /// Explicit opt-out: the protocol deliberately binds no application context.
    #[must_use]
    pub fn without_session(self) -> DomainSeparator<I, WithSession<NoSession>> {
        self.session(NoSession)
    }
}

impl<I: ?Sized, S> DomainSeparator<WithoutInstance<I>, WithSession<S>> {
    pub fn instance(self, value: &I) -> DomainSeparator<WithInstance<'_, I>, WithSession<S>> {
        DomainSeparator {
            protocol: self.protocol,
            session: self.session,
            instance: WithInstance(value),
        }
    }
}

impl<I, S> DomainSeparator<WithInstance<'_, I>, WithSession<S>>
where
    I: Encoding,
    S: Encoding,
{
    #[cfg(feature = "sha3")]
    pub fn std_prover(&self) -> ProverState {
        self.to_prover(StdHash::default())
    }

    #[cfg(feature = "sha3")]
    pub fn std_verifier<'ver>(&self, narg_string: &'ver [u8]) -> VerifierState<'ver, StdHash> {
        self.to_verifier(StdHash::default(), narg_string)
    }
}

impl<I, S> DomainSeparator<WithInstance<'_, I>, WithSession<S>> {
    pub fn to_prover<H>(&self, h: H) -> ProverState<H, StdRng>
    where
        H: DuplexSpongeInterface,
        [u8; 64]: Encoding<[H::U]>,
        S: Encoding<[H::U]>,
        I: Encoding<[H::U]>,
    {
        let mut prover_state = ProverState::from(h);
        prover_state.public_message(&self.protocol);
        prover_state.public_message(&self.session.0);
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
        verifier_state.public_message(&self.session.0);
        verifier_state.public_message(self.instance.0);
        verifier_state
    }
}

#[inline]
fn hash_bytes_to_array(bytes: &[u8]) -> [u8; 64] {
    let mut sponge = StdHash::default();
    sponge.absorb(bytes);
    sponge.squeeze_array()
}

#[inline]
fn hash_args_to_array(args: Arguments) -> [u8; 64] {
    args.as_str().map_or_else(
        || hash_bytes_to_array(alloc::fmt::format(args).as_bytes()),
        |message| hash_bytes_to_array(message.as_bytes()),
    )
}

/// Hashes a protocol identifier into a 64-byte array.
#[inline]
#[must_use]
pub fn protocol_id(args: Arguments) -> [u8; 64] {
    hash_args_to_array(args)
}

/// Hashes a session label into a 64-byte array.
#[inline]
#[must_use]
pub fn session_id(args: Arguments) -> [u8; 64] {
    hash_args_to_array(args)
}

/// Hashes a string into a 64-byte array.
#[inline]
#[doc(hidden)]
#[must_use]
pub fn session_id_from_str<S>(value: &S) -> [u8; 64]
where
    S: AsRef<str> + ?Sized,
{
    hash_bytes_to_array(value.as_ref().as_bytes())
}
