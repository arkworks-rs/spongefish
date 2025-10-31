use core::fmt::Arguments;

use rand::rngs::StdRng;

#[cfg(feature = "sha3")]
use crate::VerifierState;
use crate::{DuplexSpongeInterface, Encoding, ProverState, StdHash};

/// A domain separator for a Fiat-Shamir transformation.
pub struct DomainSeparator<S, I> {
    pub protocol_id: [u8; 64],
    pub session_id: S,
    pub instance: I,
}

impl<S, I> DomainSeparator<S, I> {
    pub fn new(protocol_id: [u8; 64], session_id: S, instance: I) -> Self {
        Self {
            session_id,
            protocol_id,
            instance,
        }
    }
}
impl<I> DomainSeparator<&[u8], I>
where
    I: Encoding,
{
    #[cfg(feature = "sha3")]
    pub fn std_prover(&self) -> ProverState {
        let mut prover_state = ProverState::default();
        prover_state.public_message(&self.protocol_id);
        prover_state.public_message(self.session_id);
        prover_state.public_message(&self.instance);
        prover_state
    }

    #[cfg(feature = "sha3")]
    pub fn std_verifier<'ver>(&self, narg_string: &'ver [u8]) -> VerifierState<'ver, StdHash> {
        let mut prover_state = VerifierState::default_std(narg_string);
        prover_state.public_message(&self.protocol_id);
        prover_state.public_message(self.session_id);
        prover_state.public_message(&self.instance);
        prover_state
    }
}

impl<S, I> DomainSeparator<S, I> {
    pub fn to_prover<H>(&self, h: H) -> ProverState<H, StdRng>
    where
        H: DuplexSpongeInterface,
        [u8; 64]: Encoding<[H::U]>,
        S: Encoding<[H::U]>,
        I: Encoding<[H::U]>,
    {
        let mut prover_state = ProverState::from(h);
        prover_state.public_message(&self.protocol_id);
        prover_state.public_message(&self.session_id);
        prover_state.public_message(&self.instance);
        prover_state
    }
}

#[inline]
pub fn protocol_id(args: Arguments) -> [u8; 64] {
    let mut sponge = StdHash::default();

    if let Some(message) = args.as_str() {
        absorb_session_input(&mut sponge, message);
    } else {
        let formatted = alloc::fmt::format(args);
        absorb_session_input(&mut sponge, &formatted);
    }

    sponge.squeeze_array::<64>()
}

#[inline]
pub fn session_id(args: Arguments) -> [u8; 64] {
    let mut sponge = StdHash::default();

    if let Some(message) = args.as_str() {
        absorb_session_input(&mut sponge, message);
    } else {
        let formatted = alloc::fmt::format(args);
        absorb_session_input(&mut sponge, &formatted);
    }

    sponge.squeeze_array::<64>()
}

#[allow(dead_code)]
fn absorb_session_input(sponge: &mut StdHash, message: &str) {
    sponge.absorb(message.as_bytes());
}
