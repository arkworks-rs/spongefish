use alloc::vec::Vec;
use core::fmt;

use crate::{
    Decoding, DuplexSpongeInterface, Encoding, NargDeserialize, StdHash, VerificationError,
    VerificationResult,
};

/// [`VerifierState`] is the verifier state.
///
/// ```
/// use spongefish::{StdHash, VerifierState};
///
/// let verifier = VerifierState::from_parts(StdHash::default(), b"extra bytes");
/// assert!(verifier.check_eof().is_err());
///
/// let verifier = VerifierState::from_parts(StdHash::default(), b"");
/// assert!(verifier.check_eof().is_ok());
/// ```
pub struct VerifierState<'a, H = StdHash>
where
    H: DuplexSpongeInterface,
{
    /// The public coins for the protocol.
    #[cfg(feature = "yolocrypto")]
    pub duplex_sponge_state: H,
    #[cfg(not(feature = "yolocrypto"))]
    pub(crate) duplex_sponge_state: H,
    /// The NARG string currently read.
    pub(crate) narg_string: &'a [u8],
}

impl<H: DuplexSpongeInterface> VerifierState<'_, H> {
    /// Reads a prover message and absorbs it into the duplex sponge state.
    pub fn prover_message<T: Encoding<[H::U]> + NargDeserialize>(
        &mut self,
    ) -> VerificationResult<T> {
        let message = T::deserialize_from_narg(&mut self.narg_string)?;
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        Ok(message)
    }

    /// Absorbs a public message without consuming the transcript.
    ///
    /// ```
    /// let proof = [0u8; 0];
    /// let mut verifier = spongefish::domain_separator!("examples";"VerifierState::public_message")
    ///     .instance(&0u32)
    ///     .std_verifier(&proof);
    /// verifier.public_message(&123u32);
    /// assert!(verifier.check_eof().is_ok());
    /// ```
    pub fn public_message<T: Encoding<[H::U]> + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    /// Returns a verifier message `T` that is uniformly distributed and implements `Encoding<[H::U]>`.
    pub fn verifier_message<T: Decoding<[H::U]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.duplex_sponge_state.squeeze(buf.as_mut());
        T::decode(buf)
    }

    /// Absorbs a slice of public messages.
    ///
    /// ```
    /// let mut verifier = spongefish::domain_separator!("examples"; "VerifierState::public_messages")
    ///     .instance(&0u32)
    ///     .std_verifier(&[]);
    /// verifier.public_messages(&[1u32, 2u32]);
    /// assert!(verifier.check_eof().is_ok());
    /// ```
    pub fn public_messages<T: Encoding<[H::U]>>(&mut self, messages: &[T]) {
        for message in messages {
            self.public_message(message);
        }
    }

    /// Absorbs an iterator of public messages.
    ///
    /// ```
    /// let mut verifier = spongefish::domain_separator!("examples"; "VerifierState::public_messages_iter")
    ///     .instance(&0u32)
    ///     .std_verifier(&[]);
    /// verifier.public_messages_iter([1u32, 2u32]);
    /// assert!(verifier.check_eof().is_ok());
    /// ```
    pub fn public_messages_iter<J>(&mut self, messages: J)
    where
        J: IntoIterator,
        J::Item: Encoding<[H::U]>,
    {
        messages
            .into_iter()
            .for_each(|message| self.public_message(&message));
    }

    /// Reads a fixed-size array of prover messages `T`, each implementing `Encoding<[H::U]>`.
    pub fn prover_messages<T: Encoding<[H::U]> + NargDeserialize, const N: usize>(
        &mut self,
    ) -> VerificationResult<[T; N]> {
        let result = self.prover_messages_vec::<T>(N)?;
        Ok(result.try_into().unwrap_or_else(|_| unreachable!()))
    }

    /// Reads `len` prover messages `T` into a vector, each implementing `Encoding<[H::U]>`.
    pub fn prover_messages_vec<T: Encoding<[H::U]> + NargDeserialize>(
        &mut self,
        len: usize,
    ) -> VerificationResult<Vec<T>> {
        (0..len).map(|_| self.prover_message()).collect()
    }

    /// Returns `Ok(())` if the transcript has been fully consumed, otherwise a `VerificationError`.
    pub fn check_eof(self) -> VerificationResult<()> {
        if self.narg_string.is_empty() {
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
    /// Builds a verifier using the default sponge implementation.
    #[must_use]
    pub fn default_std(narg_string: &'a [u8]) -> Self {
        VerifierState {
            duplex_sponge_state: StdHash::default(),
            narg_string,
        }
    }
}

impl<'a, H: DuplexSpongeInterface> VerifierState<'a, H> {
    /// Creates a verifier state from a duplex sponge and transcript slice.
    pub const fn from_parts(duplex_sponge_state: H, narg_string: &'a [u8]) -> Self {
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
    /// Initializes a verifier state from protocol and session identifiers plus a transcript.
    #[must_use]
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
    /// Initializes a verifier with `StdHash` as duplex sponge.
    #[must_use]
    pub fn new_std(protocol_id: &[u8; 64], session_id: &[u8; 64], narg_string: &'a [u8]) -> Self {
        Self::new(protocol_id, session_id, narg_string)
    }
}
