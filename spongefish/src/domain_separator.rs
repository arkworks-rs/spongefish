use core::{fmt::Arguments, marker::PhantomData};

use rand::rngs::StdRng;

#[cfg(feature = "sha3")]
use crate::VerifierState;
use crate::{DuplexSpongeInterface, Encoding, ProverState, StdHash};

pub struct WithoutInstance<I>(PhantomData<I>);

impl<I> WithoutInstance<I> {
    const fn new() -> Self {
        Self(PhantomData)
    }
}

pub struct WithInstance<'i, I>(&'i I);

/// A domain separator for a Fiat-Shamir transformation.
pub struct DomainSeparator<S, I> {
    pub protocol_id: [u8; 64],
    pub session_info: Option<S>,
    instance: I,
}

impl<S, I> DomainSeparator<S, WithoutInstance<I>> {
    pub fn new(protocol_id: [u8; 64]) -> Self {
        Self {
            protocol_id,
            session_info: None,
            instance: WithoutInstance::new(),
        }
    }
}

impl<S, I> DomainSeparator<S, I> {
    pub fn session(self, session_info: S) -> Self {
        assert!(self.session_info.is_none());
        Self {
            instance: self.instance,
            session_info: Some(session_info),
            protocol_id: self.protocol_id,
        }
    }
}

impl<S, I> DomainSeparator<S, WithoutInstance<I>> {
    pub fn instance<'a>(self, instance: &'a I) -> DomainSeparator<S, WithInstance<'a, I>> {
        DomainSeparator {
            protocol_id: self.protocol_id,
            session_info: self.session_info,
            instance: WithInstance(instance),
        }
    }
}

impl<'a, S, I> DomainSeparator<S, WithInstance<'a, I>>
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

impl<'inst, S, I> DomainSeparator<S, WithInstance<'inst, I>> {
    pub fn to_prover<H>(&self, h: H) -> ProverState<H, StdRng>
    where
        H: DuplexSpongeInterface,
        [u8; 64]: Encoding<[H::U]>,
        S: Encoding<[H::U]>,
        I: Encoding<[H::U]>,
    {
        let mut prover_state = ProverState::from(h);
        prover_state.public_message(&self.protocol_id);
        if let Some(session_info) = &self.session_info {
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
        verifier_state.public_message(&self.protocol_id);
        if let Some(session_info) = &self.session_info {
            verifier_state.public_message(session_info);
        }
        verifier_state.public_message(self.instance.0);
        verifier_state
    }
}

#[inline]
pub fn protocol_id(args: Arguments) -> [u8; 64] {
    let mut sponge = StdHash::default();

    if let Some(message) = args.as_str() {
        sponge.absorb(message.as_bytes());
    } else {
        let formatted = alloc::fmt::format(args);
        sponge.absorb(formatted.as_bytes());
    }

    sponge.squeeze_array::<64>()
}

#[inline]
pub fn session_id(args: Arguments) -> [u8; 64] {
    let mut sponge = StdHash::default();

    if let Some(message) = args.as_str() {
        sponge.absorb(message.as_bytes());
    } else {
        let formatted = alloc::fmt::format(args);
        sponge.absorb(formatted.as_bytes());
    }

    sponge.squeeze_array::<64>()
}
