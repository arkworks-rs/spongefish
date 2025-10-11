use alloc::vec::Vec;

use rand::{CryptoRng, Rng, RngCore};

use super::{duplex_sponge::DuplexSpongeInterface, keccak::Keccak, DefaultHash, DefaultRng};
use crate::{
    codecs::{Decodable, Encodable},
    io::Serialize,
};

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
    pub(crate) csrng: ProverPrivateRng<R>,
    /// The public coins for the protocol
    pub(crate) hash_state: H,
    /// The encoded data.
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
pub struct ProverPrivateRng<R: RngCore + CryptoRng> {
    /// The duplex sponge that is used to generate the random coins.
    pub(crate) ds: Keccak,
    /// The cryptographic random number generator that seeds the sponge.
    pub(crate) csrng: R,
}

impl<R: RngCore + CryptoRng> RngCore for ProverPrivateRng<R> {
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
        self.ds.absorb(&dest[..len]);
        // fill `dest` with the output of the sponge
        self.ds.squeeze(dest);
        // erase the state from the sponge so that it can't be reverted
        self.ds.pad_block();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.ds.squeeze(dest);
        Ok(())
    }
}

impl<H, R> ProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    /// Return a reference to the random number generator associated to the proof string.
    ///
    /// ```
    /// # use spongefish::*;
    /// # use rand::RngCore;
    ///
    /// // The domain separator does not need to specify the private coins.
    /// let domain_separator = DomainSeparator::<DefaultHash>::new("📝");
    /// let mut prover_state = domain_separator.to_prover_state();
    /// assert_ne!(prover_state.rng().next_u32(), 0, "You won the lottery!");
    /// let mut challenges = [0u8; 32];
    /// prover_state.rng().fill_bytes(&mut challenges);
    /// assert_ne!(challenges, [0u8; 32]);
    /// ```
    pub fn rng(&mut self) -> &mut (impl CryptoRng + RngCore) {
        &mut self.csrng
    }

    /// Return the current proof string.
    /// The proof string contains all the serialized prover messages.
    ///
    /// ```
    /// # use spongefish::*;
    ///
    /// let domain_separator = DomainSeparator::<DefaultHash>::new("📝").absorb(8, "how to make pasta 🤌");
    /// let mut prover_state = domain_separator.to_prover_state();
    /// prover_state.add_bytes(b"1tbsp:3l").unwrap();
    /// assert_eq!(prover_state.narg_string(), b"1tbsp:3l");
    /// ```
    pub fn narg_string(&self) -> &[u8] {
        self.narg_string.as_slice()
    }

    pub fn public_message<T: Encodable<[H::U]>>(&mut self, message: &T) {
        self.hash_state.absorb(message.encode().as_ref());
    }

    pub fn prover_message<T: Encodable<[H::U]> + Serialize>(&mut self, message: &T) {
        self.hash_state.absorb(message.encode().as_ref());
        message.serialize_into(&mut self.narg_string);
    }

    pub fn verifier_message<T>(&mut self) -> T
    where
        T: Decodable,
        T::Repr: AsMut<[H::U]>,
    {
        let mut buf = T::Repr::default();
        self.hash_state.squeeze(buf.as_mut());
        T::decode(buf).into()
    }
}

impl<H, R> ProverState<H, R>
where
    H: DuplexSpongeInterface<U = u8>,
    R: RngCore + CryptoRng,
{
    pub fn new(
        protocol_id: [u8; 32],
        session_id: impl AsRef<[u8]>,
        instance_label: impl AsRef<[u8]>,
        csrng: R,
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
            hash_state,
            csrng: csrng.into(),
            narg_string: Default::default(),
        }
    }
}

impl<R: RngCore + CryptoRng> ProverPrivateRng<R> {
    pub fn reseed_with(&mut self, value: &[u8]) {
        self.ds.absorb(value);
    }

    pub fn reseed(&mut self) {
        let mut seed = [0u8; 32];
        self.csrng.fill(&mut seed);
        self.ds.absorb(&seed);
    }
}

impl<R: RngCore + CryptoRng> From<R> for ProverPrivateRng<R> {
    fn from(value: R) -> Self {
        Self {
            csrng: value,
            ds: Default::default(),
        }
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ProverPrivateRng<R> {}

impl<H, R> core::fmt::Debug for ProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProverState<{}>", core::any::type_name::<H>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover_state_add_units_and_rng_differs() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(4, "data");
        let mut pstate = ProverState::from(&domsep);

        pstate.add_bytes(&[1, 2, 3, 4]).unwrap();

        let mut buf = [0u8; 8];
        pstate.rng().fill_bytes(&mut buf);
        assert_ne!(buf, [0; 8]);
    }

    #[test]
    fn test_prover_state_public_units_does_not_affect_narg() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(4, "data");
        let mut pstate = ProverState::from(&domsep);

        pstate.public_units(&[1, 2, 3, 4]).unwrap();
        assert_eq!(pstate.narg_string(), b"");
    }

    #[test]
    fn test_prover_state_ratcheting_changes_rng_output() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").ratchet();
        let mut pstate = ProverState::from(&domsep);

        let mut buf1 = [0u8; 4];
        pstate.rng().fill_bytes(&mut buf1);

        pstate.ratchet().unwrap();

        let mut buf2 = [0u8; 4];
        pstate.rng().fill_bytes(&mut buf2);

        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_add_units_appends_to_narg_string() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(3, "msg");
        let mut pstate = ProverState::from(&domsep);
        let input = [42, 43, 44];

        assert!(pstate.add_units(&input).is_ok());
        assert_eq!(pstate.narg_string(), &input);
    }

    #[test]
    fn test_add_units_too_many_elements_should_error() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(2, "short");
        let mut pstate = ProverState::from(&domsep);

        let result = pstate.add_units(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ratchet_works_when_expected() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").ratchet();
        let mut pstate = ProverState::from(&domsep);
        assert!(pstate.ratchet().is_ok());
    }

    #[test]
    fn test_ratchet_fails_when_not_expected() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(1, "bad");
        let mut pstate = ProverState::from(&domsep);
        assert!(pstate.ratchet().is_err());
    }

    #[test]
    fn test_public_units_does_not_update_transcript() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(2, "p");
        let mut pstate = ProverState::from(&domsep);
        let _ = pstate.public_units(&[0xaa, 0xbb]);

        assert_eq!(pstate.narg_string(), b"");
    }

    #[test]
    fn test_fill_challenge_units() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").squeeze(8, "ch");
        let mut pstate = ProverState::from(&domsep);

        let mut out = [0u8; 8];
        let _ = pstate.fill_challenge_units(&mut out);
        assert_ne!(out, [0; 8]);
    }

    #[test]
    fn test_rng_entropy_changes_with_transcript() {
        let domsep = DomainSeparator::<DefaultHash>::new("t").absorb(3, "init");
        let mut p1 = ProverState::from(&domsep);
        let mut p2 = ProverState::from(&domsep);

        let mut a = [0u8; 16];
        let mut b = [0u8; 16];

        p1.rng().fill_bytes(&mut a);
        p2.add_units(&[1, 2, 3]).unwrap();
        p2.rng().fill_bytes(&mut b);

        assert_ne!(a, b);
    }

    #[test]
    fn test_add_units_multiple_accumulates() {
        let domsep = DomainSeparator::<DefaultHash>::new("t")
            .absorb(2, "a")
            .absorb(3, "b");
        let mut p = ProverState::from(&domsep);

        p.add_units(&[10, 11]).unwrap();
        p.add_units(&[20, 21, 22]).unwrap();

        assert_eq!(p.narg_string(), &[10, 11, 20, 21, 22]);
    }

    #[test]
    fn test_narg_string_round_trip_check() {
        let domsep = DomainSeparator::<DefaultHash>::new("t").absorb(5, "data");
        let mut p = ProverState::from(&domsep);

        let msg = b"zkp42";
        p.add_units(msg).unwrap();

        let encoded = p.narg_string();
        assert_eq!(encoded, msg);
    }

    #[test]
    fn test_hint_bytes_appends_hint_length_and_data() {
        let domsep: DomainSeparator<DefaultHash> =
            DomainSeparator::new("hint_test").hint("proof_hint");
        let mut prover = domsep.to_prover_state();

        let hint = b"abc123";
        prover.hint_bytes(hint).unwrap();

        // Explanation:
        // - `hint` is "abc123", which has 6 bytes.
        // - The protocol encodes this as a 4-byte *little-endian* length prefix: 6 = 0x00000006 → [6, 0, 0, 0]
        // - Then it appends the hint bytes: b"abc123"
        // - So the full expected value is:
        let expected = [6, 0, 0, 0, b'a', b'b', b'c', b'1', b'2', b'3'];

        assert_eq!(prover.narg_string(), &expected);
    }

    #[test]
    fn test_hint_bytes_empty_hint_is_encoded_correctly() {
        let domsep: DomainSeparator<DefaultHash> = DomainSeparator::new("empty_hint").hint("empty");
        let mut prover = domsep.to_prover_state();

        prover.hint_bytes(b"").unwrap();

        // Length = 0 encoded as 4 zero bytes
        assert_eq!(prover.narg_string(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_hint_bytes_fails_if_hint_op_missing() {
        let domsep: DomainSeparator<DefaultHash> = DomainSeparator::new("no_hint");
        let mut prover = domsep.to_prover_state();

        // DomainSeparator contains no hint operation
        let result = prover.hint_bytes(b"some_hint");
        assert!(
            result.is_err(),
            "Should error if no hint op in domain separator"
        );
    }

    #[test]
    fn test_hint_bytes_is_deterministic() {
        let domsep: DomainSeparator<DefaultHash> = DomainSeparator::new("det_hint").hint("same");

        let hint = b"zkproof_hint";
        let mut prover1 = domsep.to_prover_state();
        let mut prover2 = domsep.to_prover_state();

        prover1.hint_bytes(hint).unwrap();
        prover2.hint_bytes(hint).unwrap();

        assert_eq!(
            prover1.narg_string(),
            prover2.narg_string(),
            "Encoding should be deterministic"
        );
    }
}
