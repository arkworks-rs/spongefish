use alloc::vec::Vec;
use core::fmt;

use crate::{
    instantiations::dsfs, Decoding, DuplexSpongeInterface, Encoding, NargSerialize, StdHash,
};

/// The prover's private randomness: a SHAKE128 duplex sponge seeded from the
/// operating system's entropy source (or an explicit seed).
///
/// # Compartmentalization
///
/// The seed is absorbed via the `Init` pattern of draft-irtf-cfrg-fiat-shamir:
/// it occupies its own rate block and is permuted **before any other operation
/// touches the state**, so no subsequent instruction ever operates on raw seed
/// bytes. Entropy mixed in later ([`PrivateRng::mix_entropy`]) receives the
/// same treatment: each mix is zero-padded to a rate-block boundary and
/// permuted before any output is drawn.
///
/// # Interoperability with `rand`
///
/// With the optional `rand` feature, [`PrivateRng`] implements
/// [`rand_core::RngCore`] and [`rand_core::CryptoRng`], so it can be passed to
/// ecosystem samplers (`ff::Field::random`, arkworks' `UniformRand`, ...), and
/// external RNGs can be mixed in with [`PrivateRng::mix_from_rng`].
pub struct PrivateRng {
    sponge: dsfs::Shake128,
}

impl PrivateRng {
    /// The byte length of the RNG seed.
    pub const SEED_LEN: usize = 32;

    /// Seeds the RNG with 32 bytes from the operating system's entropy source.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's entropy source fails: proceeding to
    /// prove with broken randomness would compromise zero-knowledge (and, for
    /// sigma protocols, leak the witness).
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn from_os_entropy() -> Self {
        let mut seed = [0u8; Self::SEED_LEN];
        getrandom::getrandom(&mut seed).expect("operating system entropy source failed");
        Self::from_seed(seed)
    }

    /// Builds a **deterministic** RNG from a seed.
    ///
    /// # Safety
    ///
    /// This is for test vectors and reproducible tests only. Proving with a
    /// fixed or reused seed compromises zero-knowledge: two proofs generated
    /// with correlated randomness leak the witness.
    #[must_use]
    pub const fn from_seed(seed: [u8; Self::SEED_LEN]) -> Self {
        Self {
            sponge: dsfs::Shake128::new(&seed),
        }
    }

    /// Mixes additional entropy into the RNG state.
    ///
    /// The data is compartmentalized into its own permuted rate block(s), so
    /// mixed-in secrets never share a block with later operations.
    pub fn mix_entropy(&mut self, data: &[u8]) {
        self.sponge.absorb_block(data);
    }

    /// Fills `dest` with random bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.sponge.squeeze(dest);
    }

    /// Samples a value through its [`Decoding`] codec — the same
    /// distribution-preserving path used for verifier messages (for prime-field
    /// scalars: oversampled little-endian wide reduction, per the `DecodeField`
    /// of draft-irtf-cfrg-fiat-shamir).
    pub fn sample<T: Decoding<[u8]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.fill_bytes(buf.as_mut());
        T::decode(buf)
    }

    /// Mixes 32 bytes drawn from an external RNG into the state.
    #[cfg(feature = "rand")]
    pub fn mix_from_rng<R: rand_core::RngCore + rand_core::CryptoRng>(&mut self, rng: &mut R) {
        let mut buf = [0u8; Self::SEED_LEN];
        rng.fill_bytes(&mut buf);
        self.mix_entropy(&buf);
    }
}

impl fmt::Debug for PrivateRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the state: it is the prover's secret randomness.
        f.write_str("PrivateRng")
    }
}

#[cfg(feature = "rand")]
impl rand_core::RngCore for PrivateRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Self::fill_bytes(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Self::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand")]
impl rand_core::CryptoRng for PrivateRng {}

/// [`ProverState`] is the prover state in the non-interactive transformation.
///
/// It provides the **secret coins** of the prover for zero-knowledge
/// ([`ProverState::rng`]), and the hash function state for the verifier's
/// **public coins**.
///
/// Build one with [`ProverState::new`] from a 32-byte session identifier
/// ([`derive_session_id`][crate::instantiations::dsfs::KeccakDuplexSponge::derive_session_id])
/// and the encoded instance:
///
/// ```
/// # #[cfg(feature = "getrandom")]
/// # {
/// use spongefish::ProverState;
///
/// let session_id = spongefish::StdHash::derive_session_id(b"example-v00");
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
pub struct ProverState<H = StdHash>
where
    H: DuplexSpongeInterface,
{
    /// The randomness state of the prover.
    pub(crate) private_rng: PrivateRng,
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

impl<H> fmt::Debug for ProverState<H>
where
    H: DuplexSpongeInterface,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProverState<{}>", core::any::type_name::<H>())
    }
}

impl<H> ProverState<H>
where
    H: crate::duplex_sponge::DuplexSpongeInit,
{
    /// The non-interactive prover for `(session_id, instance)`, seeded from the
    /// operating system's entropy source.
    ///
    /// Per draft-irtf-cfrg-fiat-shamir, the duplex sponge is initialized with
    /// the 32-byte session identifier and the encoded instance is the first
    /// value absorbed.
    ///
    /// # Panics
    ///
    /// Panics if the encoded instance is empty (forbidden by the draft), or if
    /// the entropy source fails.
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn new<T: Encoding<[u8]> + ?Sized>(session_id: &[u8; 32], instance: &T) -> Self {
        Self::from_parts(session_id, instance, PrivateRng::from_os_entropy())
    }

    /// The non-interactive prover with a **deterministic** private RNG.
    ///
    /// # Safety
    ///
    /// For test vectors and reproducible tests only; see [`PrivateRng::from_seed`].
    #[must_use]
    pub fn new_with_seed<T: Encoding<[u8]> + ?Sized>(
        session_id: &[u8; 32],
        instance: &T,
        seed: [u8; PrivateRng::SEED_LEN],
    ) -> Self {
        Self::from_parts(session_id, instance, PrivateRng::from_seed(seed))
    }

    /// The non-interactive prover from an explicitly-constructed [`PrivateRng`].
    #[must_use]
    pub fn from_parts<T: Encoding<[u8]> + ?Sized>(
        session_id: &[u8; 32],
        instance: &T,
        private_rng: PrivateRng,
    ) -> Self {
        let mut duplex_sponge_state = H::init(session_id);
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

impl<H> ProverState<H>
where
    H: DuplexSpongeInterface,
{
    /// Returns the private RNG bound to this prover.
    pub const fn rng(&mut self) -> &mut PrivateRng {
        &mut self.private_rng
    }

    /// Mixes external entropy into the private RNG
    /// (see [`PrivateRng::mix_entropy`]).
    pub fn mix_entropy(&mut self, data: &[u8]) {
        self.private_rng.mix_entropy(data);
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
    pub fn public_message<T: Encoding<[H::U]> + ?Sized>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    /// Input a prover message of type `T` into the Fiat--Shamir transformation.
    ///
    /// `T` must implement [`Encoding<[H::U]>`][`Encoding`] to be encoded in the domain of the
    /// duplex sponge, and [`NargSerialize`] to be serialized into the NARG string.
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

impl<H> ProverState<H>
where
    H: DuplexSpongeInterface<U = u8>,
{
    /// Input a prover message using a one-off encoding closure.
    ///
    /// The bytes returned by `encode` are both absorbed into the duplex sponge
    /// and written to the NARG string — the same bytes, in the same call, as
    /// required for prover messages by draft-irtf-cfrg-fiat-shamir. This is an
    /// escape hatch for foreign types that cannot implement [`Encoding`] /
    /// [`NargSerialize`] due to the orphan rule; the closure output must follow
    /// the same rules (prefix-free on its domain).
    pub fn prover_message_with<T: ?Sized, B: AsRef<[u8]>>(
        &mut self,
        message: &T,
        encode: impl FnOnce(&T) -> B,
    ) {
        let bytes = encode(message);
        self.duplex_sponge_state.absorb(bytes.as_ref());
        self.narg_string.extend_from_slice(bytes.as_ref());
    }

    /// Absorb a public message using a one-off encoding closure
    /// (see [`ProverState::prover_message_with`]).
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

/// Creates a new [`ProverState`] with an OS-entropy-seeded RNG and an
/// **unseeded** sponge state. [`ProverState::default`] is only available with
/// the `yolocrypto` feature and its support in future releases is not
/// guaranteed.
#[cfg(all(feature = "yolocrypto", feature = "getrandom"))]
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
#[cfg(feature = "getrandom")]
impl<H: DuplexSpongeInterface> From<H> for ProverState<H> {
    fn from(value: H) -> Self {
        Self {
            duplex_sponge_state: value,
            private_rng: PrivateRng::from_os_entropy(),
            narg_string: Vec::new(),
        }
    }
}
