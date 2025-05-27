use core::slice::from_ref;
use std::slice::from_mut;

use rand::{CryptoRng, RngCore};

use super::ProverState;
use crate::{
    transcript::{Hierarchy, Interaction, InteractionError, Kind, Label, Length, Transcript},
    ChallengeProver, DuplexSpongeInterface, HintProver, MessageProver, Unit,
};

impl<H, U, R> Transcript for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    type Error = InteractionError;

    fn begin<T>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.transcript
            .interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length))
    }

    fn end<T>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.transcript
            .interact(Interaction::new::<T>(Hierarchy::End, kind, label, length))
    }
}

impl<H, U, R> MessageProver<U> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    type Error = InteractionError;

    fn message(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &U,
    ) -> Result<(), InteractionError> {
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

    fn message_fixed(&mut self, label: impl Into<Label>, value: &[U]) -> Result<(), Self::Error> {
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

    fn message_dynamic(&mut self, label: impl Into<Label>, value: &[U]) -> Result<(), Self::Error> {
        // Update transcript
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Dynamic,
        ))?;

        // Length prefix
        let length = u32::try_from(value.len())
            .expect("message larger than u32::MAX units")
            .to_le_bytes();

        // Add to duplex sponge state
        self.duplex_sponge.absorb(value);

        // Ratchet to demark end of dynamic list in duplex_sponge
        self.duplex_sponge.ratchet();

        // Add to proof string (writing to Vec<u8> is infallible)
        let old_len = self.narg_string.len();
        self.narg_string.extend_from_slice(&length);
        U::write(value, &mut self.narg_string).unwrap();
        let written = &self.narg_string[old_len..];

        // Add to Prover RNG
        self.rng.absorb(written);

        Ok(())
    }
}

impl<H, U, R> ChallengeProver<U> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    type Error = InteractionError;

    fn challenge_out(&mut self, label: impl Into<Label>, out: &mut U) -> Result<(), Self::Error> {
        // Update transcript
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Scalar,
        ))?;

        self.duplex_sponge.squeeze(from_mut(out));

        Ok(())
    }

    fn challenge_fixed(
        &mut self,
        label: impl Into<Label>,
        out: &mut [U],
    ) -> Result<(), Self::Error> {
        // Update transcript
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(out.len()),
        ))?;

        self.duplex_sponge.squeeze(out);

        Ok(())
    }

    /// Two protections are used to make sure the prover and verifier use the same length:
    ///
    /// - The length is written to the proof string as a 'hint', this prevents accidental errors.
    /// - After absorbing the duplex sponge is ratcheted, this creates an
    ///   unambiguous end of list marker
    fn challenge_dynamic(
        &mut self,
        label: impl Into<Label>,
        out: &mut [U],
    ) -> Result<(), Self::Error> {
        // Update transcript
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Dynamic,
        ))?;

        // Length prefix
        let length = u32::try_from(out.len())
            .expect("hint larger than u32::MAX bytes")
            .to_le_bytes();

        // Write length to proof string
        self.narg_string.extend_from_slice(&length);

        // Squeeze requested number of items.
        self.duplex_sponge.squeeze(out);

        // Ratchet to demark end of dynamic sized
        self.duplex_sponge.ratchet();

        Ok(())
    }
}

impl<H, U, R> HintProver<u8> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    type Error = InteractionError;

    fn hint(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &u8,
    ) -> Result<(), InteractionError> {
        self.transcript.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Scalar,
        ))?;

        // Add to proof string
        self.narg_string.push(*value);

        // Add to Prover RNG
        self.rng.absorb(from_ref(value));

        Ok(())
    }

    fn hint_fixed(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error> {
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

    fn hint_dynamic(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<[u8]>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ))?;
        // Length prefix
        let length = u32::try_from(value.len())
            .expect("hint larger than u32::MAX bytes")
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
