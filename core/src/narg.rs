use alloc::vec::Vec;

use rand::{CryptoRng, Rng, RngCore};

use crate::{
    codecs::{Decoding, Encoding},
    duplex_sponge::DuplexSpongeInterface,
    io::{Deserialize, Serialize},
    DefaultHash, VerificationResult,
};

type DefaultRng = rand::rngs::StdRng;

/// [`VerifierState`] is the verifier state.
///
/// Internally, it simply contains a stateful hash.
/// Given as input an [`DomainSeparator`] and a NARG string, it allows to
/// de-serialize elements from the NARG string and make them available to the zero-knowledge verifier.
pub struct VerifierState<'a, H = DefaultHash>
where
    H: DuplexSpongeInterface,
{
    pub(crate) duplex_sponge_state: H,
    pub(crate) narg_string: &'a [u8],
}

impl<H: DuplexSpongeInterface> VerifierState<'_, H> {
    pub fn prover_messages<T: Encoding<[H::U]> + Deserialize>(&mut self) -> VerificationResult<T> {
        let message = T::deserialize_from(&mut self.narg_string)?;
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        Ok(message)
    }

    pub fn public_message<T: Encoding<[H::U]>>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    pub fn verifier_message<T: Decoding<[H::U]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.duplex_sponge_state.squeeze(buf.as_mut());
        T::decode(buf)
    }
}

impl<H: DuplexSpongeInterface + core::fmt::Debug> core::fmt::Debug for VerifierState<'_, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("VerifierState")
            .field(&self.duplex_sponge_state)
            .finish()
    }
}

/// [`ProverState`] is the prover state the non-interactive transformation.
/// It provides the **secret coins** of the prover for zero-knowledge, and
/// the hash function state for the verifier's public coins.
///
/// [`ProverState`] works by default over bytes with [`DefaultHash`] and
/// relies on the default random number generator [`DefaultRng`].
///
/// # Safety
///
/// Leaking [`ProverState`] is equivalent to leaking the prover's private coins, and therefore zero-knowledge.
/// [`ProverState`] does not implement [`Clone`] or [`Copy`] to prevent accidental state-restoration attacks.
/// [`Default`] is implemented to provide alternative initialization methods than the one provided by [`ProverState::new`].
#[derive(Default)]
pub struct ProverState<H = DefaultHash, R = DefaultRng>
where
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    /// The randomness state of the prover.
    pub(crate) private_rng: ReseedableRng<R>,
    /// The public coins for the protocol.
    pub(crate) duplex_sponge_state: H,
    /// The argument string.
    pub(crate) narg_string: Vec<u8>,
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
    pub(crate) duplex_sponge: DefaultHash,
    /// The cryptographic random number generator that seeds the sponge.
    pub(crate) csrng: R,
}

impl<R: RngCore + CryptoRng> From<R> for ReseedableRng<R> {
    fn from(mut csrng: R) -> Self {
        let mut duplex_sponge = DefaultHash::new();
        let seed: [u8; 32] = csrng.gen::<[u8; 32]>();
        duplex_sponge.absorb(&seed);
        ReseedableRng { duplex_sponge, csrng }
    }
}

impl ReseedableRng<DefaultRng> {
    fn new() -> Self {
        use rand::SeedableRng;
        let csrng = DefaultRng::from_entropy();
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
        // Seed (at most) 32 bytes of randomness from the CSRNG
        let len = usize::min(dest.len(), 32);
        self.csrng.fill_bytes(&mut dest[..len]);
        self.duplex_sponge.absorb(&dest[..len]);
        // fill `dest` with the output of the sponge
        self.duplex_sponge.squeeze(dest);
        // erase the state from the sponge so that it can't be reverted
        self.duplex_sponge.ratchet();
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

    pub fn public_message<T: Encoding<[H::U]>>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
    }

    pub fn prover_message<T: Encoding<[H::U]> + Serialize>(&mut self, message: &T) {
        self.duplex_sponge_state.absorb(message.encode().as_ref());
        message.serialize_into(&mut self.narg_string);
    }

    pub fn verifier_message<T: Decoding<[H::U]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.duplex_sponge_state.squeeze(buf.as_mut());
        T::decode(buf)
    }
}

impl<H> ProverState<H, DefaultRng>
where
    H: DuplexSpongeInterface<U = u8>,
{
    pub fn new(
        protocol_id: [u8; 32],
        session_id: impl AsRef<[u8]>,
        instance_label: impl AsRef<[u8]>,
    ) -> Self {
        let instance_label_length = instance_label.as_ref().len().to_be_bytes();
        let session_id_length = session_id.as_ref().len().to_be_bytes();
        let mut hash_state = H::new();
        hash_state
            .absorb(protocol_id.as_ref())
            .absorb(&[0; 32])
            .absorb(&session_id_length)
            .absorb(session_id.as_ref())
            .absorb(&instance_label_length)
            .absorb(instance_label.as_ref());
        Self {
            duplex_sponge_state: hash_state,
            private_rng: ReseedableRng::new(),
            narg_string: Default::default(),
        }
    }
}

impl<R: RngCore + CryptoRng> ReseedableRng<R> {
    pub fn reseed_with(&mut self, value: &[u8]) {
        self.duplex_sponge.absorb(value);
    }

    pub fn reseed(&mut self) {
        let mut seed = [0u8; 32];
        self.csrng.fill(&mut seed);
        self.duplex_sponge.absorb(&seed);
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
