use alloc::vec::Vec;
use core::fmt;

use crate::{
    Decoding, DuplexSpongeInterface, Encoding, NargDeserialize, StdHash, VerificationError,
    VerificationResult,
};

/// [`VerifierState`] is the verifier state.
///
/// # Panics
///
/// Dropping without fully consuming the NARG string will discard potential elements of the proof,
/// and might result in the proof being malleable.
pub struct VerifierState<'a, H = StdHash>
where
    H: DuplexSpongeInterface,
{
    /// The public coins for the protocol.
    pub(crate) duplex_sponge_state: H,
    /// The NARG string currently read.
    pub(crate) narg_string: &'a [u8],
}

impl<H: DuplexSpongeInterface> VerifierState<'_, H> {
    /// Read a prover message and absorb it into the duplex sponge state.
    pub fn prover_message<T: Encoding<[H::U]> + NargDeserialize>(
        &mut self,
    ) -> VerificationResult<T> {
        let message = T::deserialize_from_narg(&mut self.narg_string)?;
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        Ok(message)
    }

    /// Absorb a public message into the duplex sponge state.
    pub fn public_message<T: Encoding<[H::U]> + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    /// Outputs a verifier challenge sampled uniformly at random.
    pub fn verifier_message<T: Decoding<[H::U]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.duplex_sponge_state.squeeze(buf.as_mut());
        T::decode(buf)
    }

    pub fn public_messages<T: Encoding<[H::U]>>(&mut self, messages: &[T]) {
        for message in messages {
            self.public_message(message)
        }
    }

    pub fn public_messages_iter<J>(&mut self, messages: J)
    where
        J: IntoIterator,
        J::Item: Encoding<[H::U]>,
    {
        messages
            .into_iter()
            .for_each(|message| self.public_message(&message))
    }

    pub fn prover_messages<T: Encoding<[H::U]> + NargDeserialize, const N: usize>(
        &mut self,
    ) -> VerificationResult<[T; N]> {
        let result = self.prover_messages_vec::<T>(N)?;
        Ok(result.try_into().unwrap_or_else(|_| unreachable!()))
    }

    pub fn prover_messages_vec<T: Encoding<[H::U]> + NargDeserialize>(
        &mut self,
        len: usize,
    ) -> VerificationResult<Vec<T>> {
        (0..len).map(|_| self.prover_message()).collect()
    }

    /// Finish the verification by checking the equation and ensuring the NARG string was fully consumed.
    pub fn finish_checking(self, equation: impl Into<bool>) -> VerificationResult<()> {
        if equation.into() && self.narg_string.is_empty() {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }
}

impl<H> fmt::Debug for VerifierState<'_, H>
where
    H: DuplexSpongeInterface,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifierState<{}>", core::any::type_name::<H>())
    }
}

impl<'a> VerifierState<'a, StdHash> {
    #[cfg(feature = "sha3")]
    pub fn default_std(narg_string: &'a [u8]) -> Self {
        VerifierState {
            duplex_sponge_state: StdHash::default(),
            narg_string,
        }
    }
}

impl<'a, H: DuplexSpongeInterface> VerifierState<'a, H> {
    pub fn from_parts(duplex_sponge_state: H, narg_string: &'a [u8]) -> Self {
        VerifierState {
            duplex_sponge_state,
            narg_string,
        }
    }
}

impl<'a, H> VerifierState<'a, H>
where
    H: DuplexSpongeInterface<U = u8> + Default,
{
    pub fn new(protocol_id: &[u8; 64], session_id: &[u8; 64], narg_string: &'a [u8]) -> Self {
        let mut verifier_state = VerifierState {
            duplex_sponge_state: H::default(),
            narg_string,
        };
        verifier_state.public_message(protocol_id);
        verifier_state.public_message(session_id);
        verifier_state
    }
}

impl<'a> VerifierState<'a, StdHash> {
    #[cfg(feature = "sha3")]
    pub fn new_std(protocol_id: &[u8; 64], session_id: &[u8; 64], narg_string: &'a [u8]) -> Self {
        Self::new(protocol_id, session_id, narg_string)
    }
}
