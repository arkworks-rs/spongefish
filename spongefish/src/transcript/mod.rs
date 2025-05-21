//! Abstract transcripts for interactive protocols.

mod interaction;
mod transcript_pattern;
mod transcript_player;
mod transcript_recorder;

use core::error::Error;

pub use self::{
    interaction::{Interaction, InteractionHierarchy, InteractionKind, Length},
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

    /// Begin of a subprotocol.
    fn begin_protocol<T>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// End of a subprotocol.
    fn end_protocol<T>(&mut self, label: &'static str) -> Result<(), Self::Error>;
}

impl<Tr: Transcript> TranscriptExt for Tr {
    type Error = Tr::Error;

    fn begin_protocol<T>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionHierarchy::Begin,
            InteractionKind::Protocol,
            label,
            Length::None,
        ))
    }

    fn end_protocol<T>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionHierarchy::Begin,
            InteractionKind::Protocol,
            label,
            Length::None,
        ))
    }
}
