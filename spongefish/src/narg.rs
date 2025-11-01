/// XXX
///
/// we are not going to provide the narg prover and verifier.
/// we provide these utilities so that the user can assemble it.
///
/// This was called transcript.
use alloc::vec::Vec;

use rand::{CryptoRng, Rng, RngCore, SeedableRng};

use crate::{
    Decoding, DuplexSpongeInterface, Encoding, NargDeserialize, NargSerialize, StdHash,
    VerificationError, VerificationResult,
};

type StdRng = rand::rngs::StdRng;

/// [`ProverState`] is the prover state the non-interactive transformation.
///
/// It provides the **secret coins** of the prover for zero-knowledge, and
/// the hash function state for the verifier's **public coins**.
///
/// [`ProverState`] works by default over bytes with [`DefaultHash`] and
/// relies on the default random number generator [`DefaultRng`].
///
/// # Safety
///
/// Leaking [`ProverState`] is equivalent to leaking the prover's private coins, and therefore zero-knowledge.
/// [`ProverState`] does not implement [`Clone`] or [`Copy`] to prevent accidental state-restoration attacks.
pub struct ProverState<H = StdHash, R = StdRng>
where
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    /// The randomness state of the prover.
    pub(crate) private_rng: ReseedableRng<R>,
    /// The public coins for the protocol.
    ///
    /// # Safety
    ///
    /// Copying this object will break the soundness guarantees installed at the [`ProverState`] level.
    /// In this release the duplex sponge state is accessible from the outside.
    pub duplex_sponge_state: H,
    /// The argument string as it gets written throughout the execution of the prover.
    pub(crate) narg_string: Vec<u8>,
}

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
    /// XXX
    pub fn prover_message<T: Encoding<[H::U]> + NargDeserialize>(
        &mut self,
    ) -> VerificationResult<T> {
        let message = T::deserialize_from_narg(&mut self.narg_string)?;
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        Ok(message)
    }

    /// XXX
    pub fn public_message<T: Encoding<[H::U]> + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    /// XXX
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
        // core::array::try_from_fn(|_| self.prover_message())
        let result = self.prover_messages_vec::<T>(N)?;
        Ok(result.try_into().unwrap_or_else(|_| unreachable!()))
    }

    pub fn prover_messages_vec<T: Encoding<[H::U]> + NargDeserialize>(
        &mut self,
        len: usize,
    ) -> VerificationResult<Vec<T>> {
        (0..len).map(|_| self.prover_message()).collect()
    }

    /// xxx
    pub fn finish(&self, equation: impl Into<bool>) -> VerificationResult<()> {
        if equation.into() && self.narg_string.is_empty() {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }
}

impl<H: DuplexSpongeInterface + core::fmt::Debug> core::fmt::Debug for VerifierState<'_, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("VerifierState")
            .field(&self.duplex_sponge_state)
            .finish()
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

/// A cryptographically-secure random number generator that is bound to the proof string.
///
/// For most public-coin protocols it is *vital* not to have two different verifier messages for the same prover message.
/// For this reason, we construct a Rng that will absorb whatever the verifier absorbs, and that in addition
/// it is seeded by a cryptographic random number generator (by default, [`rand::rngs::OsRng`]).
///
/// Every time a challenge is being generated, the private prover sponge is ratcheted, so that it can't be inverted and the randomness recovered.
#[derive(Default)]
pub struct ReseedableRng<R: RngCore + CryptoRng> {
    /// The duplex sponge that is used to generate the prover's private random coins.
    pub(crate) duplex_sponge: StdHash,
    /// The cryptographic random number generator that seeds the sponge.
    pub(crate) csrng: R,
}

impl<R: RngCore + CryptoRng> From<R> for ReseedableRng<R> {
    fn from(mut csrng: R) -> Self {
        let mut duplex_sponge = StdHash::default();
        let seed: [u8; 32] = csrng.gen::<[u8; 32]>();
        duplex_sponge.absorb(&seed);
        ReseedableRng {
            duplex_sponge,
            csrng,
        }
    }
}

impl ReseedableRng<StdRng> {
    pub fn new() -> Self {
        use rand::SeedableRng;
        let csrng = StdRng::from_entropy();
        csrng.into()
    }
}

impl<R: RngCore + CryptoRng> RngCore for ReseedableRng<R> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(buf.as_mut());
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(buf.as_mut());
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // fill `dest` with the output of the sponge
        self.duplex_sponge.squeeze(dest);
        // xxx. for extra safety we can imagine ratcheting here so that
        // the state of the sponge can't be reverted after
        // erase the state from the sponge so that it can't be reverted
        // self.duplex_sponge.ratchet();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.duplex_sponge.squeeze(dest);
        Ok(())
    }
}

impl<H, R> ProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    // xxx. todo documentation
    /// Return a reference to the random number generator associated to the proof string.
    pub const fn rng(&mut self) -> &mut ReseedableRng<R> {
        &mut self.private_rng
    }

    /// Return the current proof string.
    /// The proof string contains the serialized prover messages.
    pub fn narg_string(&self) -> &[u8] {
        self.narg_string.as_slice()
    }

    /// Declare a new public message.
    ///
    /// This function will absorb the message inside the prover's [`DuplexSpongeInterface`]
    /// but it will not serialize it inside the [`narg_string`][ProverState::narg_string].
    ///
    /// It is similar to [`prover_message`], but the input provided here will not end up
    /// in the final proof string.
    pub fn public_message<T: Encoding<[H::U]> + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    /// Declare a new prover message sent by the interactive argument.
    ///
    /// This function will absorb the prover message inside the prover's [`DuplexSpongeInterface`] instance
    /// and serialize the prover message inside the [`narg_string`][ProverState::narg_string].
    pub fn prover_message<T: Encoding<[H::U]> + NargSerialize>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        message.serialize_into_narg(&mut self.narg_string);
    }

    /// Outputs a uniformly-distributed verifier message.
    pub fn verifier_message<T: Decoding<[H::U]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.duplex_sponge_state.squeeze(buf.as_mut());
        T::decode(buf)
    }

    /// Alias for [`narg_string`][`ProverState::narg_string`].
    ///
    /// In interactive proofs, _transcript_ is the term used to denote set of prover and verifier messages.
    /// It is not the proof resulting from the Fiat-Shamir transformation.
    /// Please use [`narg_string`][`ProverState::narg_string`] instead.
    #[deprecated(note = "Please use ProverState::narg_string instead.")]
    pub fn transcript(&self) -> &[u8] {
        self.narg_string()
    }

    /// Alias for [`verifier_message`][`ProverState::verifier_message`].
    #[deprecated(note = "Please use ProverState::verifier_message instead.")]
    pub fn challenge<T: Decoding<[H::U]>>(&mut self) -> T {
        self.verifier_message()
    }

    /// xxx
    pub fn public_messages<T: Encoding<[H::U]>>(&mut self, messages: &[T]) {
        for message in messages {
            self.public_message(message)
        }
    }

    /// xxx
    pub fn public_messages_iter<J>(&mut self, messages: J)
    where
        J: IntoIterator,
        J::Item: Encoding<[H::U]>,
    {
        messages
            .into_iter()
            .for_each(|message| self.public_message(&message))
    }

    /// Absorb a list of prover messages at once.
    ///
    /// Equivalent to calling [`prover_message`][ProverState::prover_message] for each element
    /// in the list.
    pub fn prover_messages<T: Encoding<[H::U]> + NargSerialize>(&mut self, messages: &[T]) {
        for message in messages {
            self.prover_message(message);
        }
    }

    /// Produce a fixed-length list of verifier messages at once.
    ///
    /// Equivalent to calling [`verifier_message`][`ProverState::verifier_message`] for each element in the list.
    pub fn verifier_messages<T: Decoding<[H::U]>, const N: usize>(&mut self) -> [T; N] {
        core::array::from_fn(|_| self.verifier_message())
    }

    /// Produce a vector of verifier messages whose size `len` is given as input.
    ///
    /// Equivalent to calling `len` times the [`verifier_message`] function.
    pub fn verifier_messages_vec<T: Decoding<[H::U]>>(&mut self, len: usize) -> Vec<T> {
        (0..len).map(|_| self.verifier_message()).collect()
    }
}

/// Creates a new [`ProverState`] seeded using [`rand::SeedableRng::from_entropy`].
///
/// [`Default`] provides alternative initialization methods than the one via [`DomainSeparator`][`crate::DomainSeparator`].
/// [`ProverState::default`] is meant to be used as a hack and its support in future releases is not guaranteed.
impl<H: DuplexSpongeInterface + Default, R: RngCore + CryptoRng + SeedableRng> Default
    for ProverState<H, R>
{
    fn default() -> Self {
        ProverState {
            duplex_sponge_state: H::default(),
            private_rng: R::from_entropy().into(),
            narg_string: Vec::new(),
        }
    }
}

/// Creates a new [`ProverState`] using the given duplex sponge interface.
impl<H: DuplexSpongeInterface, R: RngCore + CryptoRng + SeedableRng> From<H> for ProverState<H, R> {
    fn from(value: H) -> Self {
        ProverState {
            duplex_sponge_state: value,
            private_rng: R::from_entropy().into(),
            narg_string: Vec::new(),
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

impl<R: RngCore + CryptoRng> ReseedableRng<R> {
    pub fn reseed_with(&mut self, value: &[u8]) {
        self.duplex_sponge.ratchet();
        self.duplex_sponge.absorb(value);
        self.duplex_sponge.ratchet();
    }

    pub fn reseed(&mut self) {
        let seed = self.csrng.gen::<[u8; 32]>();
        self.reseed_with(&seed);
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ReseedableRng<R> {}

impl<H, R> core::fmt::Debug for ProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProverState<{}>", core::any::type_name::<H>())
    }
}
