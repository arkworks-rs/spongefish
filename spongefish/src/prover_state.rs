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
    unit, DefaultHash, DefaultRng, ProverRng,
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

/// Convenience conversion when R is Seedable.
impl<U, H, R> From<TranscriptPattern> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng + SeedableRng,
{
    fn from(pattern: TranscriptPattern) -> Self {
        Self::from(&pattern)
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

impl<H, U, R> unit::Common<U> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    fn public_unit(&mut self, label: impl Into<Label>, value: &U) -> Result<(), Self::Error> {
        let value = from_ref(value);

        // Update transcript
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Scalar,
        ))?;

        // Add to duplex sponge state
        self.duplex_sponge.absorb(value);

        // Add to Prover RNG
        let mut buffer = Vec::new();
        U::write(value, &mut buffer).unwrap();
        self.rng.absorb(&buffer);

        Ok(())
    }

    fn public_units(&mut self, label: impl Into<Label>, value: &[U]) -> Result<(), Self::Error> {
        // Update transcript
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(value.len()),
        ))?;

        // Add to duplex sponge state
        self.duplex_sponge.absorb(value);

        // Add to Prover RNG
        let mut buffer = Vec::new();
        U::write(value, &mut buffer).unwrap();
        self.rng.absorb(&buffer);

        Ok(())
    }

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

impl<H, U, R> unit::Prover<U> for ProverState<H, U, R>
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
    use zerocopy::IntoBytes;

    use super::*;
    use crate::{transcript::TranscriptRecorder, unit::*};

    /// Test all operations in UnitPattern.
    #[test]
    fn test_prover_state_unit_pattern() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.begin_protocol::<ProverState>("test all")?;
        pattern.ratchet()?;
        pattern.public_unit("1")?;
        pattern.public_units("2", 4)?;
        pattern.message_unit("3")?;
        pattern.message_units("4", 4)?;
        pattern.challenge_unit("5")?;
        pattern.challenge_units("6", 4)?;
        pattern.hint_bytes("7", 4)?;
        pattern.hint_bytes_dynamic("8")?;
        pattern.end_protocol::<ProverState>("test all")?;
        let pattern = pattern.finalize()?;

        let mut prover: ProverState = pattern.into();
        prover.begin_protocol::<ProverState>("test all")?;
        prover.ratchet()?;
        prover.public_unit("1", &1)?;
        prover.public_units("2", 2_u32.as_bytes())?;
        prover.message_unit("3", &3)?;
        prover.message_units("4", 4_u32.as_bytes())?;
        assert_eq!(prover.challenge_unit("5")?, 128);
        assert_eq!(prover.challenge_units_array("6")?, [72, 136, 56, 161]);
        prover.hint_bytes("7", 7_u32.as_bytes())?;
        prover.hint_bytes_dynamic("8", &[8, 9, 10])?;
        prover.end_protocol::<ProverState>("test all")?;
        let proof = prover.finalize()?;

        assert_eq!(hex::encode(proof), "0304000000070000000300000008090a");

        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_drop_unfinalized_panics() {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.message_units("data", 4).unwrap();
        let pattern = pattern.finalize().unwrap();

        let mut prover: ProverState = pattern.into();
        prover.message_units("data", &[1, 2, 3, 4]).unwrap();
        // Dropping unfinalized prover state should panic
    }

    #[test]
    #[should_panic]
    fn test_ignore_error_panics() {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.message_units("data", 4).unwrap();
        let pattern = pattern.finalize().unwrap();

        let mut prover: ProverState = pattern.into();
        assert!(prover.message_units("wrong", &[1, 2, 3, 4]).is_err());

        // Resume after error should panic
        let _ = prover.message_units("data", &[1, 2, 3, 4]);
    }

    #[test]
    fn test_prover_state_add_units_and_rng_differs() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.message_units("data", 4)?;
        let pattern = pattern.finalize()?;

        let mut prover_before: ProverState = pattern.into();

        let mut prover_after = prover_before.clone();
        prover_after.message_units("data", &[1, 2, 3, 4])?;

        let before: [u8; 32] = prover_before.rng().random();
        let after: [u8; 32] = prover_after.rng().random();
        assert_ne!(before, after);

        prover_before.abort();
        prover_after.abort();

        Ok(())
    }

    #[test]
    fn test_prover_state_public_units_does_not_affect_narg() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.public_units("public units", 4)?;
        let pattern = pattern.finalize()?;

        let mut prover: ProverState = pattern.into();
        prover.public_units("public units", &[1_u8, 2, 3, 4])?;
        let proof = prover.finalize()?;

        assert_eq!(hex::encode(proof), "");
        Ok(())
    }

    #[test]
    fn test_prover_state_ratcheting_changes_rng_output() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.ratchet()?;
        let pattern = pattern.finalize()?;

        let mut prover_before: ProverState = pattern.into();

        let mut prover_after = prover_before.clone();
        prover_after.ratchet()?;

        let before: [u8; 32] = prover_before.rng().random();
        let after: [u8; 32] = prover_after.rng().random();
        assert_ne!(before, after);

        prover_before.abort();
        prover_after.abort();
        Ok(())
    }

    #[test]
    fn test_add_units_appends_to_narg_string() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.message_units("message", 3)?;
        let pattern = pattern.finalize()?;

        let mut prover: ProverState = pattern.into();
        prover.message_units("message", &[42, 43, 44])?;
        let proof = prover.finalize()?;

        assert_eq!(proof, [42, 43, 44]);
        Ok(())
    }

    #[test]
    fn test_add_units_too_many_elements_should_error() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.message_units("short", 2)?;
        let pattern = pattern.finalize()?;

        let mut prover: ProverState = pattern.into();
        let result = prover.message_units("message", &[1, 2, 3]);
        assert!(result.is_err());

        // Throwing an error also finalizes the transcript.
        Ok(())
    }

    #[test]
    fn test_ratchet_fails_when_not_expected() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.message_units("bad", 1)?;
        let pattern = pattern.finalize()?;

        let mut prover: ProverState = pattern.into();
        let result = prover.ratchet();
        assert!(matches!(
            result,
            Err(InteractionError::UnexpectedInteraction { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_fill_challenge_units() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.challenge_units("ch", 8)?;
        let pattern = pattern.finalize()?;

        let mut prover: ProverState = pattern.into();
        let out: [u8; 8] = prover.challenge_units_array("ch")?;

        assert_eq!(out, [55, 59, 25, 201, 150, 155, 112, 182]);

        prover.abort();
        Ok(())
    }

    #[test]
    fn test_rng_entropy_changes_with_transcript() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.message_units("init", 3)?;
        let pattern = pattern.finalize()?;

        let mut prover_before: ProverState = pattern.into();

        let mut prover_after = prover_before.clone();
        prover_after.message_units("init", &[1, 2, 3])?;

        let before: [u8; 32] = prover_before.rng().random();
        let after: [u8; 32] = prover_after.rng().random();
        assert_ne!(before, after);

        prover_before.abort();
        prover_after.abort();
        Ok(())
    }

    #[test]
    fn test_add_units_multiple_accumulates() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.message_units("a", 2)?;
        pattern.message_units("b", 3)?;
        let pattern = pattern.finalize()?;

        let mut prover: ProverState = pattern.into();
        prover.message_units("a", &[10, 11])?;
        prover.message_units("b", &[20, 21, 22])?;
        let proof = prover.finalize()?;

        assert_eq!(proof, [10, 11, 20, 21, 22]);
        Ok(())
    }

    #[test]
    fn test_narg_string_round_trip_check() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.message_units("data", 5)?;
        let pattern = pattern.finalize()?;

        let msg = b"zkp42";

        let mut prover: ProverState = pattern.into();
        prover.message_units("data", msg)?;
        let proof = prover.finalize()?;

        assert_eq!(proof, msg);
        Ok(())
    }
}
