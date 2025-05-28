use std::{
    marker::PhantomData,
    slice::{from_mut, from_ref},
    sync::Arc,
};

use rand::{CryptoRng, RngCore, SeedableRng};

use crate::{
    duplex_sponge::{DuplexSpongeInterface, Unit},
    transcript::{
        Hierarchy, Interaction, InteractionError, Kind, Label, Length, Transcript,
        TranscriptPattern, TranscriptPlayer,
    },
    DefaultHash, DefaultRng, ProverRng, UnitChallenge, UnitProver,
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
    transcript: TranscriptPlayer,

    /// The randomness state of the prover.
    rng: ProverRng<R>,

    /// The public coins for the protocol
    duplex_sponge: H,

    /// The encoded data.
    narg_string: Vec<u8>,

    /// Unit type of the sponge (defaults to `u8`)
    _unit: PhantomData<U>,
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
            rng: ProverRng::new(domain_separator, csrng),
            duplex_sponge: H::new(domain_separator),
            narg_string: Vec::new(),
            _unit: PhantomData,
        }
    }

    /// Terminate a proof sequence without completion
    pub fn abort(mut self) {
        // Zero sensitive state
        self.duplex_sponge.zeroize();

        // Abort the transcript (will panic on drop if not done)
        self.transcript.abort();
    }

    /// Finalize the proof and return the proof bytes on success.
    ///
    ///
    /// Dropping `ProverState` without calling finalize will result in a panic.
    ///
    /// Return the current protocol transcript.
    ///
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
    pub fn finalize(mut self) -> Result<Vec<u8>, InteractionError> {
        // Zero sensitive state
        self.duplex_sponge.zeroize();

        // Finalize the transcript (will panic if called twice)
        self.transcript.finalize()?;

        // Return proof bytes
        Ok(self.narg_string)
    }
}

/// Implementation when R is [`SeedableRng`]
impl<H, U, R> ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng + SeedableRng,
{
    /// Initialize the prover with the private random number generator seeded from operating
    /// system randomness.
    #[must_use]
    pub fn new(pattern: Arc<TranscriptPattern>) -> Self {
        Self::new_with_rng(pattern, R::from_os_rng())
    }
}

/// Convenience conversion when R is Seedable.
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

impl<H, U, R> Transcript for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    type Error = InteractionError;

    fn begin<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.transcript
            .interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length))
    }

    fn end<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.transcript
            .interact(Interaction::new::<T>(Hierarchy::End, kind, label, length))
    }
}

impl<H, U, R> UnitChallenge<U> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    fn challenge_unit_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut U,
    ) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Scalar,
        ))?;
        self.duplex_sponge.squeeze(from_mut(out));
        Ok(())
    }

    fn challenge_units_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [U],
    ) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(out.len()),
        ))?;
        self.duplex_sponge.squeeze(out);
        Ok(())
    }
}

impl<H, U, R> UnitProver<U> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    #[cfg(not(feature = "arkworks-rand"))]
    fn rng(&mut self) -> impl rand::CryptoRng {
        &mut self.rng
    }

    #[cfg(feature = "arkworks-rand")]
    fn rng(&mut self) -> impl rand::CryptoRng + ark_std::rand::CryptoRng {
        &mut self.rng
    }

    fn ratchet(&mut self) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            "ratchet",
            Length::Scalar,
        ))?;
        self.duplex_sponge.ratchet();
        self.rng.ratchet();
        Ok(())
    }

    fn message_unit(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &U,
    ) -> Result<(), Self::Error> {
        let value = from_ref(value);

        // Update transcript
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Scalar,
        ))?;

        // Add to duplex sponge state
        self.duplex_sponge.absorb(value);

        // Add to proof string (writing to Vec<u8> is infallible)
        let old_len = self.narg_string.len();
        U::write(value, &mut self.narg_string).unwrap();
        let written = &self.narg_string[old_len..];

        // Add to Prover RNG
        self.rng.absorb(written);

        Ok(())
    }

    fn message_units(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &[U],
    ) -> Result<(), Self::Error> {
        // Update transcript
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(value.len()),
        ))?;

        // Add to duplex sponge state
        self.duplex_sponge.absorb(value);

        // Add to proof string (writing to Vec<u8> is infallible)
        let old_len = self.narg_string.len();
        U::write(value, &mut self.narg_string).unwrap();
        let written = &self.narg_string[old_len..];

        // Add to Prover RNG
        self.rng.absorb(written);

        Ok(())
    }

    fn hint_bytes(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &[u8],
    ) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<[u8]>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Fixed(value.len()),
        ))?;

        // Add to proof string
        self.narg_string.extend_from_slice(value);

        // Add to Prover RNG
        self.rng.absorb(value);

        Ok(())
    }

    fn hint_bytes_dynamic(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &[u8],
    ) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<[u8]>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ))?;
        // Length prefix
        let length = u32::try_from(value.len())
            .expect("hint can not be larger than u32::MAX bytes")
            .to_le_bytes();

        // Add to proof string
        self.narg_string.extend_from_slice(&length);
        self.narg_string.extend_from_slice(value);

        // Add to Prover RNG
        self.rng.absorb(&length);
        self.rng.absorb(value);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rand::Rng;

    use super::*;
    use crate::{transcript::TranscriptRecorder, UnitPattern};

    #[test]
    fn test_prover_state_add_units_and_rng_differs() -> Result<(), Box<dyn Error>> {
        let mut recorder = TranscriptRecorder::<u8>::new();
        recorder.message_units("data", 4)?;
        let pattern = recorder.finalize()?;

        let mut pstate_before: ProverState = ProverState::from(&pattern);

        let mut pstate_after = pstate_before.clone();
        pstate_after.message_units("data", &[1, 2, 3, 4])?;

        let before: [u8; 32] = pstate_before.rng().random();
        let after: [u8; 32] = pstate_after.rng().random();
        assert_ne!(before, after);

        pstate_before.abort();
        pstate_after.abort();

        Ok(())
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
