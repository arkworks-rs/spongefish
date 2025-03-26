use rand::{CryptoRng, RngCore};

use crate::duplex_sponge::Unit;
use crate::{BytesToUnitSerialize, DomainSeparator, HashStateWithInstructions, UnitTranscript};

use super::duplex_sponge::DuplexSpongeInterface;
use super::keccak::Keccak;
use super::{DefaultHash, DefaultRng, DomainSeparatorMismatch};

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
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
    U: Unit,
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
    /// assert!(prover_state.add_bytes(&[0u8; 20]).is_ok());
    /// let result = prover_state.add_bytes(b"1tbsp every 10 liters");
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
    /// // The IO Pattern does not need to specify the private coins.
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
