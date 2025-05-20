mod interaction;
mod transcript_pattern;
mod transcript_player;
mod transcript_recorder;

use core::error::Error;

pub use self::{
    interaction::{Interaction, InteractionKind, Length},
    transcript_pattern::{TranscriptError, TranscriptPattern},
    transcript_player::{InteractionError, TranscriptPlayer},
    transcript_recorder::TranscriptRecorder,
};

/// Generic trait for transcripts that can process interactions.
pub trait Transcript {
    type Error: Error;

    /// Process an interaction.
    fn interact(&mut self, interaction: Interaction) -> Result<(), Self::Error>;
}

/// Extension trait for [`Transcript`].
pub trait TranscriptExt {
    type Error: Error;

    /// Scalar prover-to-verifier message.
    fn message<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// Fixed size prover-to-verifier message.
    fn message_array<T: 'static>(
        &mut self,
        label: &'static str,
        length: usize,
    ) -> Result<(), Self::Error>;

    /// Dynamic size prover-to-verifier message.
    fn message_slice<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    fn hint<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    fn challenge<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// Begin of a subprotocol.
    fn begin<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// End of a subprotocol.
    fn end<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error>;
}

impl<Tr: Transcript> TranscriptExt for Tr {
    type Error = Tr::Error;

    fn message<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionKind::Message,
            label,
            Length::Scalar,
        ))
    }

    fn message_array<T: 'static>(
        &mut self,
        label: &'static str,
        length: usize,
    ) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionKind::Message,
            label,
            Length::Fixed(length),
        ))
    }

    fn message_slice<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionKind::Message,
            label,
            Length::Dynamic,
        ))
    }

    fn hint<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionKind::Hint,
            label,
            Length::Scalar,
        ))
    }

    fn challenge<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionKind::Challenge,
            label,
            Length::Scalar,
        ))
    }

    fn begin<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionKind::Begin,
            label,
            Length::None,
        ))
    }

    fn end<T: 'static>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionKind::End,
            label,
            Length::None,
        ))
    }
}
