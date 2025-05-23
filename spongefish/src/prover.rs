use std::{marker::PhantomData, sync::Arc};

use rand::{CryptoRng, RngCore, SeedableRng};

use crate::{
    duplex_sponge::{DuplexSpongeInterface, Unit},
    transcript::{InteractionError, TranscriptPattern, TranscriptPlayer},
    BytesToUnitSerialize, DefaultHash, DefaultRng, DomainSeparatorMismatch, ProverPrivateRng,
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
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProverState<H = DefaultHash, U = u8, R = DefaultRng>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    /// The transcript being followed.
    pub(crate) transcript: TranscriptPlayer,
    /// The randomness state of the prover.
    pub(crate) rng: ProverPrivateRng<R>,
    /// The public coins for the protocol
    pub(crate) duplex_sponge: H,
    /// The encoded data.
    pub(crate) narg_string: Vec<u8>,
    /// Unit type of the sponge (defaults to `u8`)
    _unit: PhantomData<U>,
}

impl<H, U, R> ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng + SeedableRng,
{
    /// Initialize the prover with the private random number generator seeded from operating
    /// system randomness.
    pub fn new(pattern: Arc<TranscriptPattern>) -> Self {
        Self::new_with_rng(pattern, R::from_os_rng())
    }
}

impl<H, U, R> ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    pub fn new_with_rng(pattern: Arc<TranscriptPattern>, csrng: R) -> Self {
        let domain_separator = pattern.domain_separator();
        Self {
            transcript: TranscriptPlayer::new(pattern),
            rng: ProverPrivateRng::new(domain_separator, csrng),
            duplex_sponge: H::new(domain_separator),
            narg_string: Vec::new(),
            _unit: PhantomData,
        }
    }

    /// Finalize the proof and return the proof bytes on success.
    ///
    /// Dropping `ProverState` without calling finalize will result in a panic.
    pub fn finalize(mut self) -> Result<Vec<u8>, InteractionError> {
        // Zero sensitive state
        self.duplex_sponge.zeroize();
        // TODO: Zero rng?

        // Finalize the transcript (will panic if called twice)
        self.transcript.finalize()?;

        // Return proof bytes
        Ok(self.narg_string)
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
    #[cfg(not(feature = "arkworks-algebra"))]
    pub fn rng(&mut self) -> &mut (impl CryptoRng + RngCore) {
        &mut self.rng
    }
    #[cfg(feature = "arkworks-algebra")]
    pub fn rng(
        &mut self,
    ) -> &mut (impl CryptoRng + RngCore + ark_std::rand::CryptoRng + ark_std::rand::RngCore) {
        &mut self.rng
    }

    pub fn hint_bytes(&mut self, hint: &[u8]) -> Result<(), InteractionError> {
        todo!(); // self.hash_state.hint()?;
        let len = u32::try_from(hint.len()).expect("Hint size out of bounds");
        self.narg_string.extend_from_slice(&len.to_le_bytes());
        self.narg_string.extend_from_slice(hint);
        Ok(())
    }

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
        todo!(); // self.hash_state.absorb(input)?;

        // write never fails on Vec<u8>
        U::write(input, &mut self.narg_string).unwrap();
        self.rng.absorb(&self.narg_string[old_len..]);

        Ok(())
    }

    /// Ratchet the verifier's state.
    pub fn ratchet(&mut self) -> Result<(), DomainSeparatorMismatch> {
        todo!(); // self.hash_state.ratchet()
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
        todo!(); // self.hash_state.squeeze(output)
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

impl<U, H, R> From<&TranscriptPattern> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng + SeedableRng,
{
    fn from(pattern: &TranscriptPattern) -> Self {
        let pattern = Arc::new(pattern.clone());
        Self::new(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::{
        Hierarchy, Interaction, Kind, Length, Transcript, TranscriptExt, TranscriptRecorder,
    };

    #[test]
    fn test_prover_state_add_units_and_rng_differs() {
        let mut recorder = TranscriptRecorder::new();
        recorder.begin_protocol::<ProverState>("test");
        recorder.interact(Interaction::new::<[u8]>(
            Hierarchy::Atomic,
            Kind::Message,
            "data",
            Length::Fixed(4),
        ));
        recorder.end_protocol::<ProverState>("test");
        let pattern = recorder.finalize().unwrap();

        let mut pstate: ProverState = ProverState::from(&pattern);

        pstate.add_bytes(&[1, 2, 3, 4]).unwrap();

        let mut buf = [0u8; 8];
        pstate.rng().fill_bytes(&mut buf);
        assert_ne!(buf, [0; 8]);
    }

    // #[test]
    // fn test_prover_state_public_units_does_not_affect_narg() {
    //     let mut recorder = TranscriptRecorder::new();
    //     recorder.begin_protocol("test");
    //     recorder.interact(Interaction::new::<[u8]>(
    //         Hierarchy::Atomic,
    //         Kind::Message,
    //         "data",
    //         Length::Fixed(4),
    //     ));
    //     recorder.end_protocol("test");
    //     let pattern = recorder.finalize().unwrap();

    //     let mut pstate = ProverState::from(&pattern);

    //     pstate.public_units(&[1, 2, 3, 4]).unwrap();
    //     assert_eq!(pstate.narg_string(), b"");
    // }

    // #[test]
    // fn test_prover_state_ratcheting_changes_rng_output() {
    //     let domsep = DomainSeparator::<DefaultHash>::new("test").ratchet();
    //     let mut pstate = ProverState::from(&domsep);

    //     let mut buf1 = [0u8; 4];
    //     pstate.rng().fill_bytes(&mut buf1);

    //     pstate.ratchet().unwrap();

    //     let mut buf2 = [0u8; 4];
    //     pstate.rng().fill_bytes(&mut buf2);

    //     assert_ne!(buf1, buf2);
    // }

    // #[test]
    // fn test_add_units_appends_to_narg_string() {
    //     let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(3, "msg");
    //     let mut pstate = ProverState::from(&domsep);
    //     let input = [42, 43, 44];

    //     assert!(pstate.add_units(&input).is_ok());
    //     assert_eq!(pstate.narg_string(), &input);
    // }

    // #[test]
    // fn test_add_units_too_many_elements_should_error() {
    //     let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(2, "short");
    //     let mut pstate = ProverState::from(&domsep);

    //     let result = pstate.add_units(&[1, 2, 3]);
    //     assert!(result.is_err());
    // }

    // #[test]
    // fn test_ratchet_works_when_expected() {
    //     let domsep = DomainSeparator::<DefaultHash>::new("test").ratchet();
    //     let mut pstate = ProverState::from(&domsep);
    //     assert!(pstate.ratchet().is_ok());
    // }

    // #[test]
    // fn test_ratchet_fails_when_not_expected() {
    //     let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(1, "bad");
    //     let mut pstate = ProverState::from(&domsep);
    //     assert!(pstate.ratchet().is_err());
    // }

    // #[test]
    // fn test_public_units_does_not_update_transcript() {
    //     let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(2, "p");
    //     let mut pstate = ProverState::from(&domsep);
    //     let _ = pstate.public_units(&[0xaa, 0xbb]);

    //     assert_eq!(pstate.narg_string(), b"");
    // }

    // #[test]
    // fn test_fill_challenge_units() {
    //     let domsep = DomainSeparator::<DefaultHash>::new("test").squeeze(8, "ch");
    //     let mut pstate = ProverState::from(&domsep);

    //     let mut out = [0u8; 8];
    //     let _ = pstate.fill_challenge_units(&mut out);
    //     assert_eq!(out, [77, 249, 17, 180, 176, 109, 121, 62]);
    // }

    // #[test]
    // fn test_rng_entropy_changes_with_transcript() {
    //     let domsep = DomainSeparator::<DefaultHash>::new("t").absorb(3, "init");
    //     let mut p1 = ProverState::from(&domsep);
    //     let mut p2 = ProverState::from(&domsep);

    //     let mut a = [0u8; 16];
    //     let mut b = [0u8; 16];

    //     p1.rng().fill_bytes(&mut a);
    //     p2.add_units(&[1, 2, 3]).unwrap();
    //     p2.rng().fill_bytes(&mut b);

    //     assert_ne!(a, b);
    // }

    // #[test]
    // fn test_add_units_multiple_accumulates() {
    //     let domsep = DomainSeparator::<DefaultHash>::new("t")
    //         .absorb(2, "a")
    //         .absorb(3, "b");
    //     let mut p = ProverState::from(&domsep);

    //     p.add_units(&[10, 11]).unwrap();
    //     p.add_units(&[20, 21, 22]).unwrap();

    //     assert_eq!(p.narg_string(), &[10, 11, 20, 21, 22]);
    // }

    // #[test]
    // fn test_narg_string_round_trip_check() {
    //     let domsep = DomainSeparator::<DefaultHash>::new("t").absorb(5, "data");
    //     let mut p = ProverState::from(&domsep);

    //     let msg = b"zkp42";
    //     p.add_units(msg).unwrap();

    //     let encoded = p.narg_string();
    //     assert_eq!(encoded, msg);
    // }
}
