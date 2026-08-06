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
/// let session_id = StdHash::derive_session_id(b"example-v00");
/// let verifier = VerifierState::<StdHash>::new(&session_id, b"instance", b"extra bytes");
/// assert!(verifier.check_eof().is_err());
///
/// let verifier = VerifierState::<StdHash>::new(&session_id, b"instance", b"");
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
        let mut narg_string = self.narg_string;
        let message = T::deserialize_from_narg(&mut narg_string)?;
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        self.narg_string = narg_string;
        Ok(message)
    }

    /// Absorbs a public message without consuming the transcript.
    ///
    /// ```
    /// use spongefish::{StdHash, VerifierState};
    /// let session_id = StdHash::derive_session_id(b"examples/VerifierState::public_message");
    /// let mut verifier = VerifierState::<StdHash>::new(&session_id, &0u32, &[]);
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

    /// Returns a fixed-length array of uniformly-distributed verifier messages `[T; N]`.
    pub fn verifier_messages<T: Decoding<[H::U]>, const N: usize>(&mut self) -> [T; N] {
        core::array::from_fn(|_| self.verifier_message())
    }

    /// Returns a vector of uniformly-distributed verifier messages `[T; N]`.
    pub fn verifier_messages_vec<T: Decoding<[H::U]>>(&mut self, len: usize) -> Vec<T> {
        (0..len).map(|_| self.verifier_message()).collect()
    }

    /// Absorbs a slice of public messages.
    ///
    /// ```
    /// use spongefish::{StdHash, VerifierState};
    /// let session_id = StdHash::derive_session_id(b"examples/VerifierState::public_messages");
    /// let mut verifier = VerifierState::<StdHash>::new(&session_id, &0u32, &[]);
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
    /// use spongefish::{StdHash, VerifierState};
    /// let session_id = StdHash::derive_session_id(b"examples/VerifierState::public_messages_iter");
    /// let mut verifier = VerifierState::<StdHash>::new(&session_id, &0u32, &[]);
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

    /// The Fiat--Shamir transformation produces a NARG string with
    /// **fixed, deterministic length**.
    /// This check ensures that no trailing bytes remain in the transcript.
    ///
    /// ```
    /// # use spongefish::{StdHash, VerifierState};
    /// let session_id = StdHash::derive_session_id(b"examples/check_eof");
    /// let verifier = VerifierState::<StdHash>::new(&session_id, b"instance", b"extra");
    /// assert!(verifier.check_eof().is_err());
    ///
    /// let verifier = VerifierState::<StdHash>::new(&session_id, b"instance", b"");
    /// assert!(verifier.check_eof().is_ok());
    /// ```
    ///
    /// # Safety
    ///
    /// Skipping this check can introduce a security vulnerability:
    /// extra bytes at the end allow an attacker to append garbage bytes to a valid proof,
    /// leading to a proof that **lacks strong simulation extractability**.
    /// A NARG string that fails this check should be rejected.
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
    H: crate::duplex_sponge::DuplexSpongeInit,
{
    /// The non-interactive verifier for `(session_id, instance, narg_string)`.
    ///
    /// Per draft-irtf-cfrg-fiat-shamir, the duplex sponge is initialized with
    /// the 32-byte session identifier and the encoded instance is the first
    /// value absorbed — exactly as the prover does ([`ProverState::new`][crate::ProverState::new]).
    ///
    /// # Panics
    ///
    /// Panics if the encoded instance is empty (forbidden by the draft).
    #[must_use]
    pub fn new<T: Encoding<[u8]> + ?Sized>(
        session_id: &[u8; 32],
        instance: &T,
        narg_string: &'a [u8],
    ) -> Self {
        let mut duplex_sponge_state = H::init(session_id);
        let encoded = instance.encode();
        assert!(
            !encoded.as_ref().is_empty(),
            "the encoded instance must be non-empty"
        );
        duplex_sponge_state.absorb(encoded.as_ref());
        VerifierState {
            duplex_sponge_state,
            narg_string,
        }
    }
}

impl<H> VerifierState<'_, H>
where
    H: DuplexSpongeInterface<U = u8>,
{
    /// Reads a prover message with a one-off deserialization closure, absorbing
    /// exactly the bytes it consumed.
    ///
    /// The dual of [`ProverState::prover_message_with`][crate::ProverState::prover_message_with]:
    /// `deserialize` reads a value from the front of the unread NARG string and
    /// advances it; the consumed bytes are absorbed verbatim.
    pub fn prover_message_with<T>(
        &mut self,
        deserialize: impl FnOnce(&mut &[u8]) -> VerificationResult<T>,
    ) -> VerificationResult<T> {
        let mut remaining = self.narg_string;
        let message = deserialize(&mut remaining)?;
        let consumed = self.narg_string.len() - remaining.len();
        self.duplex_sponge_state
            .absorb(&self.narg_string[..consumed]);
        self.narg_string = remaining;
        Ok(message)
    }

    /// Absorb a public message using a one-off encoding closure
    /// (see [`ProverState::public_message_with`][crate::ProverState::public_message_with]).
    pub fn public_message_with<T: ?Sized, B: AsRef<[u8]>>(
        &mut self,
        message: &T,
        encode: impl FnOnce(&T) -> B,
    ) {
        self.duplex_sponge_state.absorb(encode(message).as_ref());
    }

    /// Derive a verifier message by squeezing `n` bytes and mapping them
    /// through a one-off decoding closure, which must preserve the uniform
    /// distribution of its input (see [`Decoding`]).
    pub fn verifier_message_with<T>(&mut self, n: usize, decode: impl FnOnce(&[u8]) -> T) -> T {
        let mut buf = alloc::vec![0u8; n];
        self.duplex_sponge_state.squeeze(&mut buf);
        decode(&buf)
    }
}
