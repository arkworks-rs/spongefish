use super::{
    Hierarchy, Interaction, Kind, Label, Length, Transcript, TranscriptError, TranscriptPattern,
};

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct TranscriptRecorder(TranscriptPattern);

impl TranscriptRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn finalize(self) -> Result<TranscriptPattern, TranscriptError> {
        self.0.validate()?;
        Ok(self.0)
    }

    pub fn interact(&mut self, interaction: Interaction) -> Result<(), TranscriptError> {
        self.0.push(interaction)
    }
}

impl Transcript for TranscriptRecorder {
    type Error = TranscriptError;

    fn begin<T>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length))
    }

    fn end<T>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length))
    }
}
