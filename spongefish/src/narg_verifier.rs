use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "turboshake128")]
use crate::StdHash;
use crate::{
    Decoding, DuplexSpongeInterface, Encoding, NargDeserialize, NargReader, SessionId,
    VerificationError, VerificationResult,
};

/// [`VerifierState`] is the verifier state in the non-interactive
/// transformation.
///
/// It holds the hash function state producing the verifier's **public coins**,
/// and a cursor over the NARG string being read. Build one with
/// [`VerifierState::new`] from a 32-byte session identifier (see
/// [`derive_session_id`][crate::derive_session_id]), the encoded instance and
/// the NARG string. Once every message has been read, conclude with
/// [`VerifierState::check_eof`]:
///
/// ```
/// # #[cfg(feature = "turboshake128")]
/// # {
/// use spongefish::{StdHash, VerifierState};
///
/// let session_id = spongefish::derive_session_id::<StdHash>(b"example-v00");
/// let verifier = VerifierState::<StdHash>::new(&session_id, b"instance", b"extra bytes");
/// assert!(verifier.check_eof().is_err());
///
/// let verifier = VerifierState::<StdHash>::new(&session_id, b"instance", b"");
/// assert!(verifier.check_eof().is_ok());
/// # }
/// ```
pub struct VerifierState<
    'a,
    #[cfg(feature = "turboshake128")] H = StdHash,
    #[cfg(not(feature = "turboshake128"))] H,
> where
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
    /// Reads a prover message from the NARG string and absorbs its encoding
    /// into the duplex sponge state.
    ///
    /// The dual of
    /// [`ProverState::prover_message`][crate::ProverState::prover_message]. On
    /// failure the cursor is left unchanged and nothing is absorbed.
    pub fn prover_message<T: Encoding<[H::U]> + NargDeserialize>(
        &mut self,
    ) -> VerificationResult<T> {
        let mut reader = NargReader::new(self.narg_string);
        let message = T::deserialize_from_narg(&mut reader)?;
        let consumed = reader.consumed();
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        self.narg_string = &self.narg_string[consumed..];
        Ok(message)
    }

    /// Reads the last prover message, then enforces end of input.
    ///
    /// The dual of
    /// [`ProverState::last_prover_message`][crate::ProverState::last_prover_message]:
    /// [`VerifierState::prover_message`] followed by
    /// [`VerifierState::check_eof`], in one call that consumes the state, so
    /// the trailing-bytes check cannot be forgotten.
    pub fn last_prover_message<T: Encoding<[H::U]> + NargDeserialize>(
        mut self,
    ) -> VerificationResult<T> {
        let message = self.prover_message()?;
        self.check_eof()?;
        Ok(message)
    }

    /// Absorbs a public message without consuming the NARG string.
    ///
    /// ```
    /// # #[cfg(feature = "turboshake128")]
    /// # {
    /// use spongefish::{StdHash, VerifierState};
    /// let session_id =
    ///     spongefish::derive_session_id::<StdHash>(b"examples/VerifierState::public_message");
    /// let mut verifier = VerifierState::<StdHash>::new(&session_id, &0u32, &[]);
    /// verifier.public_message(&123u32);
    /// assert!(verifier.check_eof().is_ok());
    /// # }
    /// ```
    pub fn public_message<T: Encoding<[H::U]> + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    /// Returns a verifier message `T` that is uniformly distributed.
    ///
    /// `T` must implement [`Decoding<[H::U]>`][`Decoding`].
    pub fn verifier_message<T: Decoding<[H::U]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.duplex_sponge_state.squeeze(buf.as_mut());
        T::decode(buf)
    }

    /// Returns a fixed-length array of uniformly-distributed verifier messages `[T; N]`.
    pub fn verifier_messages<T: Decoding<[H::U]>, const N: usize>(&mut self) -> [T; N] {
        core::array::from_fn(|_| self.verifier_message())
    }

    /// Returns a vector of `len` uniformly-distributed verifier messages `T`.
    pub fn verifier_messages_vec<T: Decoding<[H::U]>>(&mut self, len: usize) -> Vec<T> {
        (0..len).map(|_| self.verifier_message()).collect()
    }

    /// Absorbs a slice of public messages.
    ///
    /// # Safety
    ///
    /// Calling this function multiple times is byte-identical to absorbing the concatenation of its elements.
    /// Therefore, the number of elements sent must be fixed by the protocol or derived from the instance,
    /// never from prover-controlled data. See
    /// [`ProverState::public_messages`][crate::ProverState::public_messages]).
    ///
    /// ```
    /// # #[cfg(feature = "turboshake128")]
    /// # {
    /// use spongefish::{StdHash, VerifierState};
    /// let session_id =
    ///     spongefish::derive_session_id::<StdHash>(b"examples/VerifierState::public_messages");
    /// let mut verifier = VerifierState::<StdHash>::new(&session_id, &0u32, &[]);
    /// verifier.public_messages(&[1u32, 2u32]);
    /// assert!(verifier.check_eof().is_ok());
    /// # }
    /// ```
    pub fn public_messages<T: Encoding<[H::U]>>(&mut self, messages: &[T]) {
        for message in messages {
            self.public_message(message);
        }
    }

    /// Absorbs an iterator of public messages.
    ///
    /// # Safety
    ///
    /// The number of messages must be fixed by the protocol; see
    /// [`VerifierState::public_messages`].
    ///
    /// ```
    /// # #[cfg(feature = "turboshake128")]
    /// # {
    /// use spongefish::{StdHash, VerifierState};
    /// let session_id =
    ///     spongefish::derive_session_id::<StdHash>(b"examples/VerifierState::public_messages_iter");
    /// let mut verifier = VerifierState::<StdHash>::new(&session_id, &0u32, &[]);
    /// verifier.public_messages_iter([1u32, 2u32]);
    /// assert!(verifier.check_eof().is_ok());
    /// # }
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

    /// Reads a prover message with deserialization and encoding closures.
    ///
    /// On failure, the NARG string is left unchanged and nothing is absorbed.
    ///
    /// On byte-oriented sponges (`H::U = u8`), prefer
    /// [`VerifierState::prover_message_as`]: it absorbs exactly the bytes the
    /// closure consumed, needing no encoding closure and leaving no room for
    /// the two maps to disagree.
    ///
    /// # Codec requirements
    ///
    /// `deserialize` must invert the prover's serialization map, and `encode`
    /// must be the very map the prover absorbed with. Both are subject to the
    /// security requirements documented on
    /// [`ProverState::prover_message_with`][crate::ProverState::prover_message_with],
    /// and any codec change **MUST** be reflected in the session tag
    /// ([draft-irtf-cfrg-fiat-shamir][FS], § "Session identifiers",
    /// requirement 2).
    ///
    /// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
    pub fn prover_message_with<T, B: AsRef<[H::U]>>(
        &mut self,
        deserialize: impl FnOnce(&mut NargReader<'_>) -> VerificationResult<T>,
        encode: impl FnOnce(&T) -> B,
    ) -> VerificationResult<T> {
        let mut reader = NargReader::new(self.narg_string);
        let message = deserialize(&mut reader)?;
        let consumed = reader.consumed();
        self.duplex_sponge_state.absorb(encode(&message).as_ref());
        self.narg_string = &self.narg_string[consumed..];
        Ok(message)
    }

    /// [`VerifierState::prover_message_with`] as a terminal
    /// (see [`VerifierState::last_prover_message`]).
    pub fn last_prover_message_with<T, B: AsRef<[H::U]>>(
        mut self,
        deserialize: impl FnOnce(&mut NargReader<'_>) -> VerificationResult<T>,
        encode: impl FnOnce(&T) -> B,
    ) -> VerificationResult<T> {
        let message = self.prover_message_with(deserialize, encode)?;
        self.check_eof()?;
        Ok(message)
    }

    /// Absorb a public message using an encoding closure
    /// (see [`ProverState::public_message_as`][crate::ProverState::public_message_as]).
    ///
    /// The closure must be the same encoding map the prover used, subject to
    /// the codec requirements documented on
    /// [`ProverState::prover_message_as`][crate::ProverState::prover_message_as].
    pub fn public_message_as<'a, T: ?Sized, B: AsRef<[H::U]>>(
        &mut self,
        message: &'a T,
        encode: impl FnOnce(&'a T) -> B,
    ) {
        self.duplex_sponge_state.absorb(encode(message).as_ref());
    }

    /// Derive a verifier message by squeezing `n` units of the sponge
    /// alphabet and mapping them through a one-off decoding closure.
    ///
    /// The closure must be distribution-preserving and infallible, and must
    /// only ever be applied to the uniform `Squeeze` output provided here;
    /// see [`ProverState::verifier_message_as`][crate::ProverState::verifier_message_as]
    /// for the full requirements. Prover and verifier must use identical
    /// decoding maps, and any change **MUST** be reflected in the session tag
    /// ([draft-irtf-cfrg-fiat-shamir][FS], § "Session identifiers",
    /// requirement 2).
    ///
    /// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
    pub fn verifier_message_as<T>(&mut self, n: usize, decode: impl FnOnce(&[H::U]) -> T) -> T {
        let buf = self.duplex_sponge_state.squeeze_boxed(n);
        decode(&buf)
    }

    /// The Fiat-Shamir transformation produces a NARG string with
    /// **fixed, deterministic length**.
    /// This check ensures that no trailing bytes remain in the NARG string.
    ///
    /// ```
    /// # #[cfg(feature = "turboshake128")]
    /// # {
    /// # use spongefish::{StdHash, VerifierState};
    /// let session_id = spongefish::derive_session_id::<StdHash>(b"examples/check_eof");
    /// let verifier = VerifierState::<StdHash>::new(&session_id, b"instance", b"extra");
    /// assert!(verifier.check_eof().is_err());
    ///
    /// let verifier = VerifierState::<StdHash>::new(&session_id, b"instance", b"");
    /// assert!(verifier.check_eof().is_ok());
    /// # }
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
    /// Creates a verifier state from a duplex sponge and a NARG string.
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
    /// Per [draft-irtf-cfrg-fiat-shamir][FS], the duplex sponge is initialized
    /// with the 32-byte session identifier and the encoded instance is the
    /// first value absorbed — exactly as the prover does
    /// ([`ProverState::new`][crate::ProverState::new]).
    ///
    /// # Panics
    ///
    /// Panics if the encoded instance is empty (forbidden by the draft).
    ///
    /// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
    #[must_use]
    pub fn new<T: Encoding<[H::U]> + ?Sized>(
        session_id: &SessionId,
        instance: &T,
        narg_string: &'a [u8],
    ) -> Self {
        let mut duplex_sponge_state = H::init(session_id.as_bytes());
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
    /// Reads a prover message with a one-off deserialization closure,
    /// absorbing exactly the bytes it consumed.
    ///
    /// The dual of
    /// [`ProverState::prover_message_as`][crate::ProverState::prover_message_as]:
    /// `deserialize` reads a value from the front of the unread NARG string
    /// and advances the cursor; the consumed bytes are then absorbed
    /// verbatim, in the same call — reading and hashing a prover message
    /// within one function call is the implementation guidance of
    /// [draft-irtf-cfrg-fiat-shamir][FS] (§ "Implementation guidance").
    ///
    /// The closure reads through a [`NargReader`] of its own, and this state only
    /// advances once the closure has succeeded.
    /// On failure the cursor is left to the previous position.
    ///
    /// For sponges over a non-byte alphabet, where the absorbed units cannot
    /// be the consumed bytes, use [`VerifierState::prover_message_with`].
    ///
    /// # Codec requirements
    ///
    /// `deserialize` must be the inverse of the prover-side encoding closure:
    /// it **MUST** reject non-canonical serializations
    /// ([FS], § "Deserialization"), and the NARG string must be treated as
    /// untrusted input — validate length indicators and integer ranges before
    /// use. The encoding it inverts must be prefix-free, with the identity
    /// admissible only on fixed-length domains ([FS], § "Codecs"; § "Byte
    /// strings" under "Serialization"). Any codec change **MUST** be reflected
    /// in the session tag ([FS], § "Session identifiers", requirement 2).
    ///
    /// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
    pub fn prover_message_as<T>(
        &mut self,
        deserialize: impl FnOnce(&mut NargReader<'_>) -> VerificationResult<T>,
    ) -> VerificationResult<T> {
        let mut reader = NargReader::new(self.narg_string);
        let message = deserialize(&mut reader)?;
        let consumed = reader.consumed();
        self.duplex_sponge_state
            .absorb(&self.narg_string[..consumed]);
        self.narg_string = &self.narg_string[consumed..];
        Ok(message)
    }

    /// [`VerifierState::prover_message_as`] as a terminal
    /// (see [`VerifierState::last_prover_message`]).
    pub fn last_prover_message_as<T>(
        mut self,
        deserialize: impl FnOnce(&mut NargReader<'_>) -> VerificationResult<T>,
    ) -> VerificationResult<T> {
        let message = self.prover_message_as(deserialize)?;
        self.check_eof()?;
        Ok(message)
    }

    /// Reads `len` prover messages into a vector through one deserialization
    /// closure.
    ///
    /// Calls [`VerifierState::prover_message_as`] `len` times in order; the
    /// closure is subject to the codec requirements documented there. This is
    /// the reader for a batch sent with
    /// [`ProverState::prover_messages_as`][crate::ProverState::prover_messages_as].
    ///
    /// On failure the cursor is left at the last successfully read message,
    /// with nothing further absorbed.
    ///
    /// # Safety
    ///
    /// `len` must be fixed by the protocol or derived from the instance —
    /// never from the NARG string itself.
    pub fn prover_messages_vec_as<T>(
        &mut self,
        len: usize,
        mut deserialize: impl FnMut(&mut NargReader<'_>) -> VerificationResult<T>,
    ) -> VerificationResult<Vec<T>> {
        (0..len)
            .map(|_| self.prover_message_as(&mut deserialize))
            .collect()
    }
}
