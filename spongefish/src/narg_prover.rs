use alloc::vec::Vec;
use core::fmt;

use rand::{CryptoRng, Rng, RngCore, SeedableRng};

use crate::{Decoding, DuplexSpongeInterface, Encoding, NargSerialize, StdHash};

type StdRng = rand::rngs::StdRng;

/// [`ProverState`] is the prover state in the non-interactive transformation.
///
/// It provides the **secret coins** of the prover for zero-knowledge, and
/// the hash function state for the verifier's **public coins**.
///
/// The internal random number generator is instantiated with [`sha3::Shake128`],
/// seeded via [`rand::rngs::StdRng`].
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
    #[cfg(feature = "yolocrypto")]
    pub duplex_sponge_state: H,
    #[cfg(not(feature = "yolocrypto"))]
    pub(crate) duplex_sponge_state: H,
    /// The argument string as it gets written throughout the execution of the prover.
    pub(crate) narg_string: Vec<u8>,
}

/// A cryptographically-secure random number generator that is bound to the proof string.
///
/// For most public-coin protocols it is *vital* not to have two different verifier messages for the same prover message.
/// For this reason, we construct an RNG that absorbs whatever the verifier absorbs, and that in addition
/// is seeded by a cryptographic random number generator (by default, [`rand::rngs::OsRng`]).
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
        Self {
            duplex_sponge,
            csrng,
        }
    }
}

impl ReseedableRng<StdRng> {
    /// Creates a reseedable RNG backed by `StdRng`.
    pub fn new() -> Self {
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

impl<R: RngCore + CryptoRng> ReseedableRng<R> {
    /// Reseeds the internal sponge with the provided bytes.
    pub fn reseed_with(&mut self, value: &[u8]) {
        self.duplex_sponge.ratchet();
        self.duplex_sponge.absorb(value);
        self.duplex_sponge.ratchet();
    }

    /// Reseeds the internal sponge with fresh entropy from the CSRNG.
    pub fn reseed(&mut self) {
        let seed = self.csrng.gen::<[u8; 32]>();
        self.reseed_with(&seed);
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ReseedableRng<R> {}

impl<H, R> fmt::Debug for ProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProverState<{}>", core::any::type_name::<H>())
    }
}

impl<H, R> ProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    /// Returns the reseedable RNG bound to this transcript.
    pub const fn rng(&mut self) -> &mut ReseedableRng<R> {
        &mut self.private_rng
    }

    /// Returns the current serialized NARG string.
    #[inline]
    pub const fn narg_string(&self) -> &[u8] {
        self.narg_string.as_slice()
    }

    /// Input a public message to the Fiat--Shamir transformation.
    ///
    /// A public message in this context is a message that is shared among prover and verifier
    /// outside of the NARG, and is to be included in the Fiat--Shamir transformation but not in
    /// the final NARG string.
    ///
    /// ```
    /// use spongefish::ProverState;
    ///
    /// let mut prover_state = spongefish::domain_separator!("examples"; "ProverState::public_message")
    ///     .instance(&0u32)
    ///     .std_prover();
    /// prover_state.public_message(&123u32);
    /// assert_eq!(prover_state.narg_string(), b"");
    /// ```
    pub fn public_message<T: Encoding<[H::U]> + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    /// Input a prover message of type `T` into the Fiat--Shamir transformation.
    ///
    /// `T` must implement [`Encoding<[H::U]>`][`Encoding`] to be encoded in the domain of the
    /// duplex sponge, and [`NargSerialize`] to be serialized into the NARG string.
    ///
    /// ```
    /// use spongefish::ProverState;
    ///
    /// let mut prover_state = spongefish::domain_separator!("examples"; "ProverState::prover_message")
    ///     .instance(&0u32)
    ///     .std_prover();
    /// prover_state.prover_message(&42u32);
    /// let expected = 42u32.to_le_bytes();
    /// assert_eq!(prover_state.narg_string(), expected.as_slice());
    /// ```
    pub fn prover_message<T: Encoding<[H::U]> + NargSerialize + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        message.serialize_into_narg(&mut self.narg_string);
    }

    /// Returns a verifier message `T` that is uniformly distributed.
    ///
    /// `T` must implement [`Decoding<[H::U]>`][`Decoding`].
    pub fn verifier_message<T: Decoding<[H::U]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.duplex_sponge_state.squeeze(buf.as_mut());
        T::decode(buf)
    }

    /// Alias for [`narg_string`][ProverState::narg_string].
    #[deprecated(note = "Please use ProverState::narg_string instead.")]
    #[inline]
    pub const fn transcript(&self) -> &[u8] {
        self.narg_string()
    }

    /// Alias for [`verifier_message`][`ProverState::verifier_message`].
    #[deprecated(note = "Please use ProverState::verifier_message instead.")]
    pub fn challenge<T: Decoding<[H::U]>>(&mut self) -> T {
        self.verifier_message()
    }

    /// Input to the Fiat--Shamir transformation an array of public messages.
    pub fn public_messages<T: Encoding<[H::U]>>(&mut self, messages: &[T]) {
        for message in messages {
            self.public_message(message);
        }
    }

    /// Input to the Fiat--Shamir transformation an iterator of public messages.
    pub fn public_messages_iter<J>(&mut self, messages: J)
    where
        J: IntoIterator,
        J::Item: Encoding<[H::U]>,
    {
        messages
            .into_iter()
            .for_each(|message| self.public_message(&message));
    }

    /// Absorbs a list of prover messages at once.
    pub fn prover_messages<T: Encoding<[H::U]> + NargSerialize>(&mut self, messages: &[T]) {
        for message in messages {
            self.prover_message(message);
        }
    }

    /// Absorbs an iterator of prover messages.
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

    /// Returns a vector of uniformly-distributed verifier messages `[T; N]`.
    pub fn verifier_messages_vec<T: Decoding<[H::U]>>(&mut self, len: usize) -> Vec<T> {
        (0..len).map(|_| self.verifier_message()).collect()
    }
}

/// Creates a new [`ProverState`] seeded using [`rand::SeedableRng::from_entropy`].
///
/// [`Default`] provides alternative initialization methods than the one via
/// [`DomainSeparator`][`crate::DomainSeparator`].
/// [`ProverState::default`] is only available with the `yolocrypto` feature and its support in
/// future releases is not guaranteed.
#[cfg(feature = "yolocrypto")]
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
        Self {
            duplex_sponge_state: value,
            private_rng: R::from_entropy().into(),
            narg_string: Vec::new(),
        }
    }
}
