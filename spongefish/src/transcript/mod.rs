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

    /// Begin of group interaction.
    fn begin<T>(&mut self, label: &'static str, kind: InteractionKind) -> Result<(), Self::Error>;

    /// End of group interaction.
    fn end<T>(&mut self, label: &'static str, kind: InteractionKind) -> Result<(), Self::Error>;

    /// Begin of a subprotocol.
    fn begin_protocol<T>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// End of a subprotocol.
    fn end_protocol<T>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// Begin of a message interaction.
    fn begin_message<T>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// End of a message interaction.
    fn end_message<T>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// Begin of a hint interaction.
    fn begin_hint<T>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// End of a hint interaction..
    fn end_hint<T>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// Begin of a challenge interaction..
    fn begin_challenge<T>(&mut self, label: &'static str) -> Result<(), Self::Error>;

    /// End of a challenge interaction..
    fn end_challenge<T>(&mut self, label: &'static str) -> Result<(), Self::Error>;
}

impl<Tr: Transcript> TranscriptExt for Tr {
    type Error = Tr::Error;

    fn begin<T>(&mut self, label: &'static str, kind: InteractionKind) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionHierarchy::Begin,
            kind,
            label,
            Length::None,
        ))
    }

    fn end<T>(&mut self, label: &'static str, kind: InteractionKind) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            InteractionHierarchy::Begin,
            kind,
            label,
            Length::None,
        ))
    }

    fn begin_protocol<T>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.begin::<T>(label, InteractionKind::Protocol)
    }

    fn end_protocol<T>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.end::<T>(label, InteractionKind::Protocol)
    }

    fn begin_message<T>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.begin::<T>(label, InteractionKind::Message)
    }

    fn end_message<T>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.end::<T>(label, InteractionKind::Message)
    }

    fn begin_hint<T>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.begin::<T>(label, InteractionKind::Hint)
    }

    fn end_hint<T>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.end::<T>(label, InteractionKind::Hint)
    }

    fn begin_challenge<T>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.begin::<T>(label, InteractionKind::Challenge)
    }

    fn end_challenge<T>(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.end::<T>(label, InteractionKind::Challenge)
    }
}
