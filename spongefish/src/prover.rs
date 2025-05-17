use rand::{CryptoRng, RngCore};

use super::{
    duplex_sponge::DuplexSpongeInterface, keccak::Keccak, DefaultHash, DefaultRng,
    DomainSeparatorMismatch,
};
use crate::{
    duplex_sponge::Unit, BytesToUnitSerialize, DomainSeparator, HashStateWithInstructions,
    UnitTranscript,
};

/// [`ProverState`] is the prover state of an interactive proof (IP) system.
/// It internally holds the **secret coins** of the prover for zero-knowledge, and
/// has the hash function state for the verifier state.
///
/// Unless otherwise specified,
/// [`ProverState`] is set to work over bytes with [`DefaultHash`] and
/// rely on the default random number generator [`DefaultRng`].
///
///
/// # Safety
///
/// The prover state is meant to be private in contexts where zero-knowledge is desired.
/// Leaking the prover state *will* leak the prover's private coins and as such it will compromise the zero-knowledge property.
/// [`ProverState`] does not implement [`Clone`] or [`Copy`] to prevent accidental leaks.
pub struct ProverState<H = DefaultHash, U = u8, R = DefaultRng>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    /// The randomness state of the prover.
    pub(crate) rng: ProverPrivateRng<R>,
    /// The public coins for the protocol
    pub(crate) hash_state: HashStateWithInstructions<H, U>,
    /// The encoded data.
    pub(crate) narg_string: Vec<u8>,
}

/// A cryptographically-secure random number generator that is bound to the protocol transcript.
///
/// For most public-coin protocols it is *vital* not to have two different verifier messages for the same prover message.
/// For this reason, we construct a Rng that will absorb whatever the verifier absorbs, and that in addition
/// it is seeded by a cryptographic random number generator (by default, [`rand::rngs::OsRng`]).
///
/// Every time a challenge is being generated, the private prover sponge is ratcheted, so that it can't be inverted and the randomness recovered.
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
        self.ds.absorb_unchecked(&dest[..len]);
        // fill `dest` with the output of the sponge
        self.ds.squeeze_unchecked(dest);
        // erase the state from the sponge so that it can't be reverted
        self.ds.ratchet_unchecked();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.ds.squeeze_unchecked(dest);
        Ok(())
    }
}

impl<H, U, R> ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    pub fn new(domain_separator: &DomainSeparator<H, U>, csrng: R) -> Self {
        let hash_state = HashStateWithInstructions::new(domain_separator);

        let mut duplex_sponge = Keccak::default();
        duplex_sponge.absorb_unchecked(domain_separator.as_bytes());
        let rng = ProverPrivateRng {
            ds: duplex_sponge,
            csrng,
        };

        Self {
            rng,
            hash_state,
            narg_string: Vec::new(),
        }
    }

    pub fn hint_bytes(&mut self, hint: &[u8]) -> Result<(), DomainSeparatorMismatch> {
        self.hash_state.hint()?;
        let len = u32::try_from(hint.len()).expect("Hint size out of bounds");
        self.narg_string.extend_from_slice(&len.to_le_bytes());
        self.narg_string.extend_from_slice(hint);
        Ok(())
    }
}

impl<U, H> From<&DomainSeparator<H, U>> for ProverState<H, U, DefaultRng>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    fn from(domain_separator: &DomainSeparator<H, U>) -> Self {
        Self::new(domain_separator, DefaultRng::default())
    }
}

impl<H, U, R> ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    /// Add a slice `[U]` to the protocol transcript.
    /// The messages are also internally encoded in the protocol transcript,
    /// and used to re-seed the prover's random number generator.
    ///
    /// ```
    /// use spongefish::{DomainSeparator, DefaultHash, BytesToUnitSerialize};
    ///
    /// let domain_separator = DomainSeparator::<DefaultHash>::new("📝").absorb(20, "how not to make pasta 🤌");
    /// let mut prover_state = domain_separator.to_prover_state();
    /// assert!(prover_state.add_units(&[0u8; 20]).is_ok());
    /// let result = prover_state.add_units(b"1tbsp every 10 liters");
    /// assert!(result.is_err())
    /// ```
    pub fn add_units(&mut self, input: &[U]) -> Result<(), DomainSeparatorMismatch> {
        let old_len = self.narg_string.len();
        self.hash_state.absorb(input)?;
        // write never fails on Vec<u8>
        U::write(input, &mut self.narg_string).unwrap();
        self.rng.ds.absorb_unchecked(&self.narg_string[old_len..]);

        Ok(())
    }

    /// Ratchet the verifier's state.
    pub fn ratchet(&mut self) -> Result<(), DomainSeparatorMismatch> {
        self.hash_state.ratchet()
    }

    /// Return a reference to the random number generator associated to the protocol transcript.
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
        &mut self.rng
    }

    /// Return the current protocol transcript.
    /// The protocol transcript does not have any information about the length or the type of the messages being read.
    /// This is because the information is considered pre-shared within the [`DomainSeparator`].
    /// Additionally, since the verifier challenges are deterministically generated from the prover's messages,
    /// the transcript does not hold any of the verifier's messages.
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
}

impl<H, U, R> UnitTranscript<U> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    /// Add public messages to the protocol transcript.
    /// Messages input to this function are not added to the protocol transcript.
    /// They are however absorbed into the verifier's sponge for Fiat-Shamir, and used to re-seed the prover state.
    ///
    /// ```
    /// # use spongefish::*;
    ///
    /// let domain_separator = DomainSeparator::<DefaultHash>::new("📝").absorb(20, "how not to make pasta 🙉");
    /// let mut prover_state = domain_separator.to_prover_state();
    /// assert!(prover_state.public_bytes(&[0u8; 20]).is_ok());
    /// assert_eq!(prover_state.narg_string(), b"");
    /// ```
    fn public_units(&mut self, input: &[U]) -> Result<(), DomainSeparatorMismatch> {
        let len = self.narg_string.len();
        self.add_units(input)?;
        self.narg_string.truncate(len);
        Ok(())
    }

    /// Fill a slice with uniformly-distributed challenges from the verifier.
    fn fill_challenge_units(&mut self, output: &mut [U]) -> Result<(), DomainSeparatorMismatch> {
        self.hash_state.squeeze(output)
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ProverPrivateRng<R> {}

impl<H, U, R> core::fmt::Debug for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.hash_state.fmt(f)
    }
}

impl<H, R> BytesToUnitSerialize for ProverState<H, u8, R>
where
    H: DuplexSpongeInterface<u8>,
    R: RngCore + CryptoRng,
{
    fn add_bytes(&mut self, input: &[u8]) -> Result<(), DomainSeparatorMismatch> {
        self.add_units(input)
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
        assert_eq!(out, [77, 249, 17, 180, 176, 109, 121, 62]);
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
}
