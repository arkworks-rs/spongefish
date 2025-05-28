use std::{fmt::Display, marker::PhantomData};

use super::{
    Hierarchy, Interaction, Kind, Label, Length, Transcript, TranscriptError, TranscriptPattern,
};
use crate::{Unit, UnitPattern};

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct TranscriptRecorder<U>
where
    U: Unit,
{
    transcript: TranscriptPattern,
    _unit: PhantomData<U>,
}

impl<U> TranscriptRecorder<U>
where
    U: Unit,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            transcript: TranscriptPattern::new(),
            _unit: PhantomData,
        }
    }

    pub fn finalize(self) -> Result<TranscriptPattern, TranscriptError> {
        self.transcript.validate()?;
        Ok(self.transcript)
    }

    pub fn interact(&mut self, interaction: Interaction) -> Result<(), TranscriptError> {
        self.transcript.push(interaction)
    }
}

impl<U> Default for TranscriptRecorder<U>
where
    U: Unit,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Allow printing of partial transcripts.
impl<U> Display for TranscriptRecorder<U>
where
    U: Unit,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unfinalized Transcript: {}", self.transcript)
    }
}

impl<U> Transcript for TranscriptRecorder<U>
where
    U: Unit,
{
    type Error = TranscriptError;

    fn begin<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length))
    }

    fn end<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length))
    }
}

impl<U> UnitPattern<U> for TranscriptRecorder<U>
where
    U: Unit,
{
    fn ratchet(&mut self) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            "ratchet",
            Length::Scalar,
        ))
    }

    fn message_unit(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Scalar,
        ))
    }

    fn message_units(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(size),
        ))
    }

    fn challenge_unit(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Scalar,
        ))
    }

    fn challenge_units(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(size),
        ))
    }

    fn hint_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<[u8]>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Fixed(size),
        ))
    }

    fn hint_bytes_dynamic(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<[u8]>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ))
    }
}
