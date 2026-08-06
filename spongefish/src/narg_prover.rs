use alloc::vec::Vec;
use core::fmt;
#[cfg(not(feature = "turboshake128"))]
use core::marker::PhantomData;

use rand::{CryptoRng, Rng, SeedableRng};
#[cfg(feature = "turboshake128")]
use rand::{RngExt, TryCryptoRng, TryRng};

#[cfg(feature = "turboshake128")]
use crate::StdHash;
use crate::{
    duplex_sponge::DuplexSpongeInit, Decoding, DuplexSpongeInterface, Encoding, NargSerialize,
};

type StdRng = rand::rngs::StdRng;
#[cfg(feature = "turboshake128")]
type PrivateRng<R> = ReseedableRng<R>;
#[cfg(not(feature = "turboshake128"))]
type PrivateRng<R> = PhantomData<R>;

/// [`ProverState`] is the prover state in the non-interactive transformation.
///
/// It provides the **secret coins** of the prover for zero-knowledge, and
/// the hash function state for the verifier's **public coins**.
///
/// Build one with [`ProverState::new`] from a 32-byte session identifier
/// (see [`derive_session_id`][crate::derive_session_id]) and the encoded
/// instance, or with [`ProverState::from_tag`] directly from an
/// application tag:
///
/// ```
/// # #[cfg(feature = "turboshake128")]
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
/// # Safety
///
/// Leaking [`ProverState`] is equivalent to leaking the prover's private coins, and therefore zero-knowledge.
/// [`ProverState`] does not implement [`Clone`] or [`Copy`] to prevent accidental state-restoration attacks.
pub struct ProverState<
    #[cfg(feature = "turboshake128")] H = StdHash,
    #[cfg(not(feature = "turboshake128"))] H,
    R = StdRng,
> where
    H: DuplexSpongeInterface,
    R: Rng + CryptoRng,
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

/// A cryptographically-secure random number generator bound to a duplex
/// sponge, seeded by a cryptographic random number generator.
///
/// The seed occupies its own rate block (the `Init` pattern of
/// draft-irtf-cfrg-fiat-shamir) and is permuted before any output is drawn;
/// entropy mixed in later is likewise zero-padded to a rate-block boundary.
#[cfg(feature = "turboshake128")]
pub struct ReseedableRng<R: Rng + CryptoRng> {
    pub(crate) duplex_sponge: StdHash,
    pub(crate) csrng: R,
}

#[cfg(feature = "turboshake128")]
impl<R: Rng + CryptoRng> From<R> for ReseedableRng<R> {
    fn from(mut csrng: R) -> Self {
        let seed: [u8; 32] = csrng.random();
        Self {
            duplex_sponge: StdHash::init(&seed),
            csrng,
        }
    }
}

#[cfg(feature = "turboshake128")]
impl Default for ReseedableRng<StdRng> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "turboshake128")]
impl ReseedableRng<StdRng> {
    /// Creates a reseedable RNG backed by `StdRng`.
    pub fn new() -> Self {
        let csrng: StdRng = rand::make_rng();
        csrng.into()
    }
}

#[cfg(feature = "turboshake128")]
impl<R: Rng + CryptoRng> TryRng for ReseedableRng<R> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.duplex_sponge.squeeze(buf.as_mut());
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.duplex_sponge.squeeze(buf.as_mut());
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.duplex_sponge.squeeze(dest);
        Ok(())
    }
}

#[cfg(feature = "turboshake128")]
impl<R: Rng + CryptoRng> ReseedableRng<R> {
    /// Reseeds the internal sponge with the provided bytes, zero-padded into
    /// their own permuted rate block(s).
    pub fn reseed_with(&mut self, value: &[u8]) {
        const RATE: usize = 168;
        const ZEROS: [u8; RATE] = [0u8; RATE];
        if value.is_empty() {
            return;
        }
        self.duplex_sponge.absorb(value);
        let rem = value.len() % RATE;
        if rem != 0 {
            self.duplex_sponge.absorb(&ZEROS[..RATE - rem]);
        }
    }

    /// Reseeds the internal sponge with fresh entropy from the CSRNG.
    pub fn reseed(&mut self) {
        let seed = self.csrng.random::<[u8; 32]>();
        self.reseed_with(&seed);
    }
}

#[cfg(feature = "turboshake128")]
impl<R: Rng + CryptoRng> TryCryptoRng for ReseedableRng<R> {}

impl<H, R> fmt::Debug for ProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: Rng + CryptoRng,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProverState<{}>", core::any::type_name::<H>())
    }
}

impl<H, R> ProverState<H, R>
where
    H: DuplexSpongeInit,
    R: Rng + CryptoRng + SeedableRng,
{
    /// The non-interactive prover for `(session_id, instance)`.
    ///
    /// Per draft-irtf-cfrg-fiat-shamir, the duplex sponge is initialized with
    /// the 32-byte session identifier and the encoded instance is the first
    /// value absorbed.
    ///
    /// # Panics
    ///
    /// Panics if the encoded instance is empty (forbidden by the draft).
    #[must_use]
    pub fn new<T: Encoding<[u8]> + ?Sized>(session_id: &[u8; 32], instance: &T) -> Self {
        let mut duplex_sponge_state = H::init(session_id);
        let encoded = instance.encode();
        assert!(
            !encoded.as_ref().is_empty(),
            "the encoded instance must be non-empty"
        );
        duplex_sponge_state.absorb(encoded.as_ref());
        Self {
            #[cfg(feature = "turboshake128")]
            private_rng: rand::make_rng::<R>().into(),
            #[cfg(not(feature = "turboshake128"))]
            private_rng: PhantomData,
            duplex_sponge_state,
            narg_string: Vec::new(),
        }
    }

    /// The non-interactive prover for `(tag, instance)`: derives the 32-byte
    /// session identifier from the application tag (the draft's
    /// `DeriveSessionID`) and calls [`ProverState::new`].
    #[must_use]
    pub fn from_tag<T: Encoding<[u8]> + ?Sized>(tag: &[u8], instance: &T) -> Self {
        Self::new(&crate::derive_session_id::<H>(tag), instance)
    }
}

impl<H, R> ProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: Rng + CryptoRng,
{
    /// Returns the reseedable RNG bound to this transcript.
    #[cfg(feature = "turboshake128")]
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
    /// # #[cfg(feature = "turboshake128")]
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

    /// Input a prover message of type `T` into the Fiat--Shamir transformation.
    ///
    /// `T` must implement [`Encoding<[H::U]>`][`Encoding`] to be encoded in the domain of the
    /// duplex sponge, and [`NargSerialize`] to be serialized into the NARG string.
    ///
    /// ```
    /// # #[cfg(feature = "turboshake128")]
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

    /// Returns a verifier message `T` that is uniformly distributed.
    ///
    /// `T` must implement [`Decoding<[H::U]>`][`Decoding`].
    pub fn verifier_message<T: Decoding<[H::U]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.duplex_sponge_state.squeeze(buf.as_mut());
        T::decode(buf)
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

/// Creates a new [`ProverState`] with an OS-seeded RNG and an **unseeded**
/// sponge state.
///
/// [`ProverState::default`] is only available with the `yolocrypto` feature and
/// its support in future releases is not guaranteed.
#[cfg(feature = "yolocrypto")]
impl<H: DuplexSpongeInterface + Default, R: Rng + CryptoRng + SeedableRng> Default
    for ProverState<H, R>
{
    fn default() -> Self {
        Self {
            duplex_sponge_state: H::default(),
            #[cfg(feature = "turboshake128")]
            private_rng: rand::make_rng::<R>().into(),
            #[cfg(not(feature = "turboshake128"))]
            private_rng: PhantomData,
            narg_string: Vec::new(),
        }
    }
}

/// Creates a new [`ProverState`] using the given duplex sponge interface.
impl<H: DuplexSpongeInterface, R: Rng + CryptoRng + SeedableRng> From<H> for ProverState<H, R> {
    fn from(value: H) -> Self {
        Self {
            duplex_sponge_state: value,
            #[cfg(feature = "turboshake128")]
            private_rng: rand::make_rng::<R>().into(),
            #[cfg(not(feature = "turboshake128"))]
            private_rng: PhantomData,
            narg_string: Vec::new(),
        }
    }
}
