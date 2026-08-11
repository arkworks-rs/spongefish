use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "turboshake128")]
use crate::StdHash;
use crate::{
    duplex_sponge::DuplexSpongeInit, Decoding, DuplexSpongeInterface, Encoding, NargSerialize,
    PrivateRng, SessionId,
};

/// [`ProverState`] is the prover state in the non-interactive transformation.
///
/// It provides the **secret coins** of the prover for zero-knowledge
/// ([`ProverState::rng`]), and the hash function state for the verifier's
/// **public coins**.
///
/// Build one with [`ProverState::new`] from a 32-byte session identifier
/// (see [`derive_session_id`][crate::derive_session_id]) and the encoded
/// instance:
///
/// ```
/// # #[cfg(feature = "getrandom")]
/// # {
/// use spongefish::ProverState;
///
/// let session_id = spongefish::derive_session_id::<spongefish::StdHash>(b"example-v00");
/// let mut prover_state = ProverState::<spongefish::StdHash>::new(&session_id, b"instance");
/// prover_state.prover_message(&42u32);
/// let narg_string = prover_state.narg_string();
/// # }
/// ```
///
/// The private RNG is a [`PrivateRng`] over `R`, independently of the sponge
/// `H` carrying the public coins.
///
/// # Safety
///
/// Leaking [`ProverState`] is equivalent to leaking the prover's private
/// coins, and therefore to losing zero-knowledge. [`ProverState`] does not
/// implement [`Clone`] or [`Copy`] to prevent accidental state-restoration
/// attacks.
pub struct ProverState<
    #[cfg(feature = "turboshake128")] H = StdHash,
    #[cfg(not(feature = "turboshake128"))] H,
    #[cfg(feature = "turboshake128")] R = StdHash,
    #[cfg(not(feature = "turboshake128"))] R,
> where
    H: DuplexSpongeInterface,
    R: DuplexSpongeInit<U = u8>,
{
    /// The randomness state of the prover.
    pub(crate) private_rng: PrivateRng<R>,
    /// The public coins for the protocol.
    ///
    /// # Safety
    ///
    /// Copying this object will break the soundness guarantees installed at the [`ProverState`] level.
    #[cfg(feature = "yolocrypto")]
    pub duplex_sponge_state: H,
    #[cfg(not(feature = "yolocrypto"))]
    pub(crate) duplex_sponge_state: H,
    /// The argument string as it gets written throughout the execution of the prover.
    pub(crate) narg_string: Vec<u8>,
}

impl<H, R> fmt::Debug for ProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: DuplexSpongeInit<U = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProverState<{}>", core::any::type_name::<H>())
    }
}

impl<H, R> ProverState<H, R>
where
    H: DuplexSpongeInit,
    R: DuplexSpongeInit<U = u8>,
{
    /// The non-interactive prover for `(session_id, instance)`, seeded from
    /// the operating system's entropy source.
    ///
    /// Per [draft-irtf-cfrg-fiat-shamir][FS], the duplex sponge is initialized
    /// with the 32-byte session identifier and the encoded instance is the
    /// first value absorbed.
    ///
    /// # Panics
    ///
    /// Panics if the encoded instance is empty (forbidden by the draft), or if
    /// the entropy source fails.
    ///
    /// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn new<T: Encoding<[H::U]> + ?Sized>(session_id: &SessionId, instance: &T) -> Self {
        Self::from_parts(session_id, instance, PrivateRng::<R>::from_os_entropy())
    }

    /// The non-interactive prover with a **deterministic** private RNG.
    ///
    /// # Safety
    ///
    /// For test vectors and reproducible tests only; see [`PrivateRng::from_seed`].
    #[must_use]
    pub fn new_with_seed<T: Encoding<[H::U]> + ?Sized>(
        session_id: &SessionId,
        instance: &T,
        seed: [u8; crate::private_rng::SEED_LEN],
    ) -> Self {
        Self::from_parts(session_id, instance, PrivateRng::<R>::from_seed(seed))
    }

    /// The non-interactive prover from an explicitly-constructed [`PrivateRng`].
    ///
    /// # Panics
    ///
    /// Panics if the encoded instance is empty (forbidden by the draft).
    #[must_use]
    pub fn from_parts<T: Encoding<[H::U]> + ?Sized>(
        session_id: &SessionId,
        instance: &T,
        private_rng: PrivateRng<R>,
    ) -> Self {
        let mut duplex_sponge_state = H::init(session_id.as_bytes());
        let encoded = instance.encode();
        assert!(
            !encoded.as_ref().is_empty(),
            "the encoded instance must be non-empty"
        );
        duplex_sponge_state.absorb(encoded.as_ref());
        Self {
            private_rng,
            duplex_sponge_state,
            narg_string: Vec::new(),
        }
    }
}

impl<H, R> ProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: DuplexSpongeInit<U = u8>,
{
    /// Returns the private RNG bound to this prover.
    pub const fn rng(&mut self) -> &mut PrivateRng<R> {
        &mut self.private_rng
    }

    /// Mixes external entropy into the private RNG
    /// (see [`PrivateRng::mix_entropy`]).
    pub fn mix_entropy(&mut self, data: &[u8; crate::private_rng::SEED_LEN]) {
        self.private_rng.mix_entropy(data);
    }

    /// Returns the current serialized NARG string.
    #[inline]
    pub const fn narg_string(&self) -> &[u8] {
        self.narg_string.as_slice()
    }

    /// Consumes the state and returns the NARG string.
    ///
    /// The terminal for a transcript whose last move is a verifier message or
    /// a public message. When the last move is a prover message, send it with
    /// [`ProverState::last_prover_message`] instead.
    #[must_use]
    pub fn into_narg_string(self) -> Vec<u8> {
        self.narg_string
    }

    /// Input a public message to the Fiat-Shamir transformation.
    ///
    /// A public message in this context is a message that is shared among prover and verifier
    /// outside of the NARG, and is to be included in the Fiat-Shamir transformation but not in
    /// the final NARG string.
    ///
    /// ```
    /// # #[cfg(feature = "getrandom")]
    /// # {
    /// use spongefish::{ProverState, StdHash};
    ///
    /// let session_id =
    ///     spongefish::derive_session_id::<StdHash>(b"examples/ProverState::public_message");
    /// let mut prover_state = ProverState::<StdHash>::new(&session_id, &0u32);
    /// prover_state.public_message(&123u32);
    /// assert_eq!(prover_state.narg_string(), b"");
    /// # }
    /// ```
    pub fn public_message<T: Encoding<[H::U]> + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    /// Input a prover message of type `T` into the Fiat-Shamir transformation.
    ///
    /// `T` must implement [`Encoding<[H::U]>`][`Encoding`] to be encoded in the domain of the
    /// duplex sponge, and [`NargSerialize`] to be serialized into the NARG string.
    ///
    /// ```
    /// # #[cfg(feature = "getrandom")]
    /// # {
    /// use spongefish::{ProverState, StdHash};
    ///
    /// let session_id =
    ///     spongefish::derive_session_id::<StdHash>(b"examples/ProverState::prover_message");
    /// let mut prover_state = ProverState::<StdHash>::new(&session_id, &0u32);
    /// prover_state.prover_message(&42u32);
    /// let expected = 42u32.to_le_bytes();
    /// assert_eq!(prover_state.narg_string(), expected.as_slice());
    /// # }
    /// ```
    pub fn prover_message<T: Encoding<[H::U]> + NargSerialize + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        message.serialize_into_narg(&mut self.narg_string);
    }

    /// Input the last prover message and return the NARG string.
    ///
    /// This function runs [`ProverState::prover_message`] consuming the prover state and
    /// returning the NARG string ([`ProverState::narg_string`]).
    #[must_use]
    pub fn last_prover_message<T: Encoding<[H::U]> + NargSerialize + ?Sized>(
        mut self,
        message: &T,
    ) -> Vec<u8> {
        self.prover_message(message);
        self.narg_string
    }

    /// Returns a verifier message `T` that is uniformly distributed.
    ///
    /// `T` must implement [`Decoding<[H::U]>`][`Decoding`].
    pub fn verifier_message<T: Decoding<[H::U]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.duplex_sponge_state.squeeze(buf.as_mut());
        T::decode(buf)
    }

    /// Input to the Fiat-Shamir transformation a slice of public messages.
    ///
    /// # Safety
    ///
    /// Calling this function multiple times is byte-identical to absorbing the concatenation of its elements.
    /// Therefore, the number of elements sent must be fixed by the protocol or derived from the instance,
    /// never from prover-controlled data. For variable-length data, send a [`LengthPrefixed`][crate::LengthPrefixed]
    /// sequence instead.
    pub fn public_messages<T: Encoding<[H::U]>>(&mut self, messages: &[T]) {
        for message in messages {
            self.public_message(message);
        }
    }

    /// Input to the Fiat-Shamir transformation an iterator of public messages.
    ///
    /// # Safety
    ///
    /// The number of messages must be fixed by the protocol; see
    /// [`ProverState::public_messages`].
    pub fn public_messages_iter<J>(&mut self, messages: J)
    where
        J: IntoIterator,
        J::Item: Encoding<[H::U]>,
    {
        messages
            .into_iter()
            .for_each(|message| self.public_message(&message));
    }

    /// Input a slice of prover messages: each is absorbed into the duplex
    /// sponge and serialized into the NARG string, in order.
    ///
    /// # Safety
    ///
    /// Calling this function multiple times is identical to absorbing the concatenation of its elements.
    /// Therefore, the number of elements sent must be fixed by the protocol or derived from the instance,
    /// never from prover-controlled data. For variable-length data, send a [`LengthPrefixed`][crate::LengthPrefixed]
    pub fn prover_messages<T: Encoding<[H::U]> + NargSerialize>(&mut self, messages: &[T]) {
        for message in messages {
            self.prover_message(message);
        }
    }

    /// Input an iterator of prover messages: each is absorbed into the duplex
    /// sponge and serialized into the NARG string, in order.
    ///
    /// # Safety
    ///
    /// The number of messages must be fixed by the protocol; see [`ProverState::prover_messages`].
    pub fn prover_messages_iter<J>(&mut self, messages: J)
    where
        J: IntoIterator,
        J::Item: Encoding<[H::U]> + NargSerialize,
    {
        messages
            .into_iter()
            .for_each(|message| self.prover_message(&message));
    }

    /// Returns a fixed-length array of uniformly-distributed verifier messages `[T; N]`.
    pub fn verifier_messages<T: Decoding<[H::U]>, const N: usize>(&mut self) -> [T; N] {
        core::array::from_fn(|_| self.verifier_message())
    }

    /// Returns a vector of `len` uniformly-distributed verifier messages `T`.
    pub fn verifier_messages_vec<T: Decoding<[H::U]>>(&mut self, len: usize) -> Vec<T> {
        (0..len).map(|_| self.verifier_message()).collect()
    }

    /// Input a prover message using encoding and serialization closures.
    ///
    /// ```
    /// # #[cfg(feature = "getrandom")]
    /// # {
    /// use spongefish::{Encoding, NargSerialize, ProverState, StdHash};
    ///
    /// let session_id =
    ///     spongefish::derive_session_id::<StdHash>(b"examples/ProverState::prover_message_with");
    /// let mut trait_path = ProverState::<StdHash>::new(&session_id, &0u32);
    /// let mut closure_path = ProverState::<StdHash>::new(&session_id, &0u32);
    ///
    /// trait_path.prover_message(&42u32);
    /// closure_path.prover_message_with(&42u32, |x| x.encode(), |x, out| x.serialize_into_narg(out));
    ///
    /// assert_eq!(trait_path.narg_string(), closure_path.narg_string());
    /// # }
    /// ```
    ///
    /// On byte-oriented sponges (`H::U = u8`), prefer [`ProverState::prover_message_as`].
    ///
    /// # Codec requirements
    ///
    /// `encode` **MUST** output a prefix-free string, with an efficiently
    /// computable left inverse ([draft-irtf-cfrg-fiat-shamir][FS], § "Codecs").
    /// Any change to either map **MUST** be reflected in the session tag
    /// ([FS], § "Session identifiers", requirement 2).
    ///
    /// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
    pub fn prover_message_with<'a, T: ?Sized, B: AsRef<[H::U]>>(
        &mut self,
        message: &'a T,
        encode: impl FnOnce(&'a T) -> B,
        serialize: impl FnOnce(&'a T, &mut Vec<u8>),
    ) {
        self.duplex_sponge_state.absorb(encode(message).as_ref());
        serialize(message, &mut self.narg_string);
    }

    /// [`ProverState::prover_message_with`] as a terminal
    /// (see [`ProverState::last_prover_message`]).
    #[must_use]
    pub fn last_prover_message_with<'a, T: ?Sized, B: AsRef<[H::U]>>(
        mut self,
        message: &'a T,
        encode: impl FnOnce(&'a T) -> B,
        serialize: impl FnOnce(&'a T, &mut Vec<u8>),
    ) -> Vec<u8> {
        self.prover_message_with(message, encode, serialize);
        self.narg_string
    }

    /// Absorb a public message using an encoding closure.
    ///
    /// Like [`ProverState::prover_message_with`] without the serialization
    /// half: a public message is shared between prover and verifier outside of
    /// the NARG string, so its encoding is only absorbed. The closure must
    /// satisfy the codec requirements documented on
    /// [`ProverState::prover_message_as`], and the verifier must absorb the
    /// same message with the same map.
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
    /// The closure is one round's decoding map `decode[i]` of
    /// [draft-irtf-cfrg-fiat-shamir][FS] (§ "Decoding from byte strings"):
    ///
    /// - It **MUST** be distribution-preserving: for a uniformly random
    ///   input, the output must be (statistically close to) uniform over the
    ///   verifier message type.
    /// - It is infallible
    /// - Its input must be uniform
    /// - Any change to the decoding (e.g. sampling verifier messages differently)
    ///   **MUST** be reflected in the session tag ([FS], § "Session identifiers", requirement 2).
    ///
    /// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
    pub fn verifier_message_as<T>(&mut self, n: usize, decode: impl FnOnce(&[H::U]) -> T) -> T {
        let buf = self.duplex_sponge_state.squeeze_boxed(n);
        decode(&buf)
    }
}

impl<H, R> ProverState<H, R>
where
    H: DuplexSpongeInterface<U = u8>,
    R: DuplexSpongeInit<U = u8>,
{
    /// Input a prover message using an encoding closure.
    ///
    /// The bytes returned by `encode` are absorbed into the duplex sponge
    /// **and** appended to the NARG string in the same call.
    /// Hashing a prover message and serializing it is done within one function call,
    /// so that messages cannot be skipped, reordered, or absorbed without being serialized.
    ///
    /// For sponges over a non-byte alphabet, where absorbed units
    /// and NARG bytes are necessarily distinct maps, use
    /// [`ProverState::prover_message_with`].
    ///
    /// # Security
    ///
    /// Following [FS], the security requirements of `encode` are:
    ///
    /// - It **MUST** be prefix-free on the message's domain ([FS], § "Codecs").
    ///   The identity encoding (`SerializeBytes`) is admissible **only** on
    ///   fixed-length domains, where prover and verifier agree on the byte
    ///   length before parsing ([FS], § "Byte strings" under "Serialization").
    /// - The security analysis additionally requires an efficiently
    ///   computable left inverse: the knowledge-soundness extractor inverts
    ///   the encoding to recover prover messages from the absorbed bytes
    ///   ([FS], § "Codecs" under "Security considerations"). In practice, make
    ///   the encoding injective and decodable.
    /// - Any change to the codec **MUST** be reflected in the session tag
    ///   ([FS], § "Session identifiers", requirement 2): two implementations
    ///   encoding messages differently must not share a session identifier.
    ///
    /// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
    pub fn prover_message_as<'a, T: ?Sized, B: AsRef<[u8]>>(
        &mut self,
        message: &'a T,
        encode: impl FnOnce(&'a T) -> B,
    ) {
        let bytes = encode(message);
        self.duplex_sponge_state.absorb(bytes.as_ref());
        self.narg_string.extend_from_slice(bytes.as_ref());
    }

    /// [`ProverState::prover_message_as`] as a terminal
    /// (see [`ProverState::last_prover_message`]).
    #[must_use]
    pub fn last_prover_message_as<'a, T: ?Sized, B: AsRef<[u8]>>(
        mut self,
        message: &'a T,
        encode: impl FnOnce(&'a T) -> B,
    ) -> Vec<u8> {
        self.prover_message_as(message, encode);
        self.narg_string
    }

    /// Input a slice of prover messages through a closure.
    ///
    /// Calls [`ProverState::prover_message_as`] on each element in order; the
    /// closure is subject to the codec requirements documented there. The
    /// verifier reads the batch back with
    /// [`VerifierState::prover_messages_vec_as`][crate::VerifierState::prover_messages_vec_as].
    ///
    /// # Safety
    ///
    /// The number of messages must be fixed by the protocol or derived from the instance.
    /// See [`ProverState::prover_messages`].
    pub fn prover_messages_as<'a, T, B: AsRef<[u8]>>(
        &mut self,
        messages: &'a [T],
        mut encode: impl FnMut(&'a T) -> B,
    ) {
        for message in messages {
            self.prover_message_as(message, &mut encode);
        }
    }
}

/// Creates a new [`ProverState`] with an OS-entropy-seeded RNG and an
/// **unseeded** sponge state.
///
/// [`ProverState::default`] is only available with the `yolocrypto` feature and
/// its support in future releases is not guaranteed.
#[cfg(all(
    feature = "yolocrypto",
    feature = "getrandom",
    feature = "turboshake128"
))]
impl<H: DuplexSpongeInterface + Default> Default for ProverState<H> {
    fn default() -> Self {
        Self {
            duplex_sponge_state: H::default(),
            private_rng: PrivateRng::from_os_entropy(),
            narg_string: Vec::new(),
        }
    }
}

/// Creates a new [`ProverState`] using the given duplex sponge interface.
#[cfg(all(feature = "getrandom", feature = "turboshake128"))]
impl<H: DuplexSpongeInterface> From<H> for ProverState<H> {
    fn from(value: H) -> Self {
        Self {
            duplex_sponge_state: value,
            private_rng: PrivateRng::from_os_entropy(),
            narg_string: Vec::new(),
        }
    }
}
