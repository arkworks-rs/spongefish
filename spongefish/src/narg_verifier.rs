use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "turboshake128")]
use crate::DefaultHash;
use crate::{
    DuplexSpongeInterface, Encoding, FromNarg, FromUniform, NargReader, SessionId,
    VerificationError,
};

/// [`VerifierState`] is the verifier state in the non-interactive
/// transformation.
///
/// It contains:
///
/// 1. The duplex sponge state, to produce verifier messages;
/// 2. A [`NargReader`] over the NARG string.
///
///
/// If de-serialization from the NARG string fails, the reader is poisoned and the duplex sponge
/// state is left at the last successful operation.
///
/// A verifier state can be instantiated via [`VerifierState::new`] from a 32-byte session identifier,
/// the encoded instance and the NARG string. Most protocols should use
/// [`Narg::verify`][crate::Narg::verify], which manages this state and always
/// enforces end of input.
///
///
/// # Example
///
/// The verifier of a Schnorr signature.
///
/// ```
/// # #[cfg(all(feature = "turboshake128", feature = "getrandom"))]
/// # {
/// use spongefish::{DefaultHash, Narg, VerifierState};
///
/// let generator = 7u32;
/// let public_key = generator.wrapping_mul(42); // the prover's witness is 42
/// let instance = [generator, public_key];
/// let session_id = Narg::derive_session_id(b"spongefish/docs/schnorr-u32/v1");
/// # let narg_string = {
/// #     let mut prover = spongefish::ProverState::<DefaultHash>::new(&session_id, &instance);
/// #     let nonce: u32 = prover.rng().sample();
/// #     prover.prover_message(&generator.wrapping_mul(nonce));
/// #     let challenge: u32 = prover.verifier_message();
/// #     prover.last_prover_message(&nonce.wrapping_add(challenge.wrapping_mul(42)))
/// # };
///
/// // `narg_string` is the output of the `ProverState` example.
/// let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &narg_string);
/// let commitment: u32 = verifier.prover_message().unwrap();
/// let challenge: u32 = verifier.verifier_message();
/// let response: u32 = verifier.last_prover_message().unwrap();
/// assert_eq!(
///     generator.wrapping_mul(response),
///     commitment.wrapping_add(challenge.wrapping_mul(public_key))
/// );
/// # }
/// ```
pub struct VerifierState<
    'a,
    #[cfg(feature = "turboshake128")] H = DefaultHash,
    #[cfg(not(feature = "turboshake128"))] H,
> where
    H: DuplexSpongeInterface,
{
    /// The public coins for the protocol.
    #[cfg(feature = "yolocrypto")]
    pub duplex_sponge_state: H,
    #[cfg(not(feature = "yolocrypto"))]
    pub(crate) duplex_sponge_state: H,
    /// The NARG string (reader)
    pub(crate) reader: NargReader<'a>,
}

impl<H: DuplexSpongeInterface> VerifierState<'_, H> {
    /// Reads a prover message from the NARG string and absorbs its encoding
    /// into the duplex sponge state.
    ///
    /// The dual of
    /// [`ProverState::prover_message`][crate::ProverState::prover_message]. On
    /// failure nothing is absorbed and the state is poisoned.
    pub fn prover_message<T: Encoding<H::U> + FromNarg>(&mut self) -> Result<T, VerificationError> {
        let (message, _) = self.read_message(T::from_narg)?;
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        Ok(message)
    }

    /// Reads the last prover message, then enforces end of input.
    ///
    /// The dual of
    /// [`ProverState::last_prover_message`][crate::ProverState::last_prover_message]:
    /// [`VerifierState::prover_message`] followed by
    /// [`VerifierState::check_eof`], in one call that consumes the state, so
    /// the trailing-bytes check cannot be forgotten.
    ///
    pub fn last_prover_message<T: Encoding<H::U> + FromNarg>(
        mut self,
    ) -> Result<T, VerificationError> {
        let message = self.prover_message()?;
        self.check_eof()?;
        Ok(message)
    }

    /// Absorbs a public message without consuming the NARG string.
    pub fn public_message<T: Encoding<H::U> + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    /// Returns a verifier message `T` that is uniformly distributed.
    ///
    /// `T` must implement [`FromUniform<H::U>`][`FromUniform`].
    #[must_use]
    pub fn verifier_message<T: FromUniform<H::U>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.duplex_sponge_state.squeeze(buf.as_mut());
        T::from_uniform(buf)
    }

    /// Returns a fixed-length array of uniformly-distributed verifier messages `[T; N]`.
    #[must_use]
    pub fn verifier_messages<T: FromUniform<H::U>, const N: usize>(&mut self) -> [T; N] {
        core::array::from_fn(|_| self.verifier_message())
    }

    /// Returns a vector of `len` uniformly-distributed verifier messages `T`.
    #[must_use]
    pub fn verifier_messages_vec<T: FromUniform<H::U>>(&mut self, len: usize) -> Vec<T> {
        (0..len).map(|_| self.verifier_message()).collect()
    }

    /// Absorbs a slice of public messages.
    ///
    /// Calling this function multiple times is identical to absorbing the sequence of its elements.
    pub fn public_messages<T: Encoding<H::U>>(&mut self, messages: &[T]) {
        for message in messages {
            self.public_message(message);
        }
    }

    /// Absorb an iterator of public messages.
    pub fn public_messages_iter<J>(&mut self, messages: J)
    where
        J: IntoIterator,
        J::Item: Encoding<H::U>,
    {
        messages
            .into_iter()
            .for_each(|message| self.public_message(&message));
    }

    /// Reads a fixed-size array of prover messages `T`, each implementing `Encoding<H::U>`.
    pub fn prover_messages<T: Encoding<H::U> + FromNarg, const N: usize>(
        &mut self,
    ) -> Result<[T; N], VerificationError> {
        let result = self.prover_messages_vec::<T>(N)?;
        Ok(result.try_into().unwrap_or_else(|_| unreachable!()))
    }

    /// Reads `len` prover messages `T` into a vector, each implementing `Encoding<H::U>`.
    /// A poisoned state rejects even an empty batch.
    pub fn prover_messages_vec<T: Encoding<H::U> + FromNarg>(
        &mut self,
        len: usize,
    ) -> Result<Vec<T>, VerificationError> {
        if self.reader.is_poisoned() {
            return Err(VerificationError);
        }
        (0..len).map(|_| self.prover_message()).collect()
    }

    /// Reads a prover message with deserialization and encoding closures.
    ///
    /// Over byte-oriented duplex sponges (`H::U = u8`), prefer
    /// [`VerifierState::prover_message_as`] which uses the same function for both encoding
    /// and serializing.
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
        deserialize: impl FnOnce(&mut NargReader<'_>) -> Result<T, VerificationError>,
        encode: impl FnOnce(&T) -> B,
    ) -> Result<T, VerificationError> {
        let (message, _) = self.read_message(deserialize)?;
        self.duplex_sponge_state.absorb(encode(&message).as_ref());
        Ok(message)
    }

    /// [`VerifierState::prover_message_with`] as a terminal
    /// (see [`VerifierState::last_prover_message`]).
    pub fn last_prover_message_with<T, B: AsRef<[H::U]>>(
        mut self,
        deserialize: impl FnOnce(&mut NargReader<'_>) -> Result<T, VerificationError>,
        encode: impl FnOnce(&T) -> B,
    ) -> Result<T, VerificationError> {
        let message = self.prover_message_with(deserialize, encode)?;
        self.check_eof()?;
        Ok(message)
    }

    /// A public prover message, with an `encode` function as a closure.
    ///
    /// See [`ProverState::public_message_as`][crate::ProverState::public_message_as].
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
    #[must_use]
    pub fn verifier_message_as<T>(&mut self, n: usize, decode: impl FnOnce(&[H::U]) -> T) -> T {
        let buf = self.duplex_sponge_state.squeeze_boxed(n);
        decode(&buf)
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
            reader: NargReader::new(narg_string),
        }
    }

    /// Read one message from the front of the NARG string.
    ///
    /// Return the message and its (serialized) bytes in the NARG string.
    ///
    /// If the reader was previously poisoned, or poisoned as a result of the `deserialize` function,
    /// the error [`VerificationError`] is returned.
    fn read_message<T>(
        &mut self,
        deserialize: impl FnOnce(&mut NargReader<'_>) -> Result<T, VerificationError>,
    ) -> Result<(T, &'a [u8]), VerificationError> {
        let before = self.reader.unread().ok_or(VerificationError)?;
        let message = self.reader.read_with(deserialize)?;
        let after = self.reader.unread().ok_or(VerificationError)?;
        Ok((message, &before[..before.len() - after.len()]))
    }

    /// Ensures that no trailing bytes remain in the NARG string.
    ///
    /// [`VerifierState::check_eof`] will return an error if the reader was previously poisoned,
    /// (for instance, when rejecting a prover message or by [`Transcript::check`][crate::Transcript::check]).
    ///
    /// # Security
    ///
    /// This function checks that the proof has no extra bytes, as they will lead to a break for
    /// **strong simulation extractability**.
    ///
    /// A NARG string that fails this check should be rejected.
    pub fn check_eof(self) -> Result<(), VerificationError> {
        if self.reader.is_empty() {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }

    /// Consumes the state and returns the unread rest of the NARG string, or
    /// an error if the state is poisoned.
    ///
    /// If empty, [`VerifierState::check_eof`] succeeds. For a
    /// proof followed by data the caller parses itself; the caller then owns
    /// the end-of-input check (see the security note on
    /// [`VerifierState::check_eof`]).
    pub fn into_narg_string(self) -> Result<&'a [u8], VerificationError> {
        self.reader.unread().ok_or(VerificationError)
    }
}

impl<'a, H> VerifierState<'a, H>
where
    H: crate::duplex_sponge::DuplexSpongeInit,
{
    /// The non-interactive verifier.
    ///
    /// The state of the verifier (and in particular, the duplex sponge state)
    /// depends entirely on `(session_id, instance, narg_string)` and the public messages
    /// provided as input.
    ///
    ///
    /// The `session_id` and `instance` are absorbed immediately into the duplex sponge state
    /// on initialization of this function.
    ///
    /// # Panics
    ///
    /// If the encoded instance is empty, this method will panic.
    ///
    /// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
    pub fn new<T: Encoding<H::U> + ?Sized>(
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
            reader: NargReader::new(narg_string),
        }
    }
}

impl<H> VerifierState<'_, H>
where
    H: DuplexSpongeInterface<U = u8>,
{
    /// Read a prover message with a deserialization closure.
    ///
    /// The prover message is fed (absorbed) into the duplex sponge `H` within this function call.
    /// If the NARG string reader is poisoned, this function will return an error
    /// and the duplex sponge state will be unaltered.
    ///
    /// The dual of
    /// [`ProverState::prover_message_as`][crate::ProverState::prover_message_as]:
    /// `deserialize` reads a value from the front of the unread NARG string
    /// and advances the cursor; the consumed bytes are then absorbed
    /// verbatim, in the same call — reading and hashing a prover message
    /// within one function call is the implementation guidance of
    /// [draft-irtf-cfrg-fiat-shamir][FS] (section "Implementation guidance").
    ///
    /// The closure reads through the state's own [`NargReader`]. On failure
    /// nothing is absorbed and the state is poisoned.
    ///
    /// For sponges over a non-byte alphabet, where the absorbed units cannot
    /// be the consumed bytes, use [`VerifierState::prover_message_with`].
    ///
    /// # Codec requirements
    ///
    /// `deserialize` must be the inverse of the prover-side encoding closure:
    /// it **MUST** reject non-canonical serializations
    /// ([FS], § "Deserialization"), and the NARG string must be treated as
    /// untrusted input: `deserialize` is subject to the same requirements as
    /// [`FromNarg::from_narg`], and in particular **MUST** return an error,
    /// never panic, on malformed input. The encoding it inverts must be prefix-free, with the identity
    /// admissible only on fixed-length domains ([FS], § "Codecs"; § "Byte
    /// strings" under "Serialization"). Any codec change **MUST** be reflected
    /// in the session tag ([FS], § "Session identifiers", requirement 2).
    ///
    /// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
    pub fn prover_message_as<T>(
        &mut self,
        deserialize: impl FnOnce(&mut NargReader<'_>) -> Result<T, VerificationError>,
    ) -> Result<T, VerificationError> {
        let (message, bytes) = self.read_message(deserialize)?;
        self.duplex_sponge_state.absorb(bytes);
        Ok(message)
    }

    /// [`VerifierState::prover_message_as`] as a terminal
    /// (see [`VerifierState::last_prover_message`]).
    pub fn last_prover_message_as<T>(
        mut self,
        deserialize: impl FnOnce(&mut NargReader<'_>) -> Result<T, VerificationError>,
    ) -> Result<T, VerificationError> {
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
    /// On failure the state is poisoned, with nothing absorbed past the last
    /// message read.
    ///
    /// # Security
    ///
    /// `len` must be fixed by the protocol or derived from the instance —
    /// never from the NARG string itself.
    pub fn prover_messages_vec_as<T>(
        &mut self,
        len: usize,
        mut deserialize: impl FnMut(&mut NargReader<'_>) -> Result<T, VerificationError>,
    ) -> Result<Vec<T>, VerificationError> {
        if self.reader.is_poisoned() {
            return Err(VerificationError);
        }
        (0..len)
            .map(|_| self.prover_message_as(&mut deserialize))
            .collect()
    }
}
