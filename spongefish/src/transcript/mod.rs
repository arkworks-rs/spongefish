//! Abstract transcripts for interactive protocols.

mod interaction;
mod transcript_pattern;
mod transcript_player;
mod transcript_recorder;

use core::error::Error;

pub use self::{
    interaction::{Hierarchy, Interaction, Kind, Label, Length},
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
pub trait TranscriptExt: Transcript {
    /// Begin of a group of interactions.
    fn begin<T>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error>;

    /// End of a group of interactions.
    fn end<T>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error>;

    /// Atomic interaction
    fn atomic<T>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error>;

    /// Begin of a subprotocol.
    fn begin_protocol<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;

    /// End of a subprotocol.
    fn end_protocol<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;

    /// Begin of a message interaction.
    fn begin_message<T>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error>;

    /// End of a message interaction.
    fn end_message<T>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error>;

    /// Begin of a hint interaction.
    fn begin_hint<T>(&mut self, label: impl Into<Label>, length: Length)
        -> Result<(), Self::Error>;

    /// End of a hint interaction..
    fn end_hint<T>(&mut self, label: impl Into<Label>, length: Length) -> Result<(), Self::Error>;

    /// Begin of a challenge interaction..
    fn begin_challenge<T>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error>;

    /// End of a challenge interaction..
    fn end_challenge<T>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error>;
}

impl<Tr: Transcript> TranscriptExt for Tr {
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

    fn atomic<T>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.interact(Interaction::new::<T>(
            Hierarchy::Atomic,
            kind,
            label,
            length,
        ))
    }

    fn begin_protocol<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        self.begin::<T>(label.into(), Kind::Protocol, Length::None)
    }

    fn end_protocol<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        self.end::<T>(label, Kind::Protocol, Length::None)
    }

    fn begin_message<T>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.begin::<T>(label, Kind::Message, length)
    }

    fn end_message<T>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.end::<T>(label, Kind::Message, length)
    }

    fn begin_hint<T>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.begin::<T>(label, Kind::Hint, length)
    }

    fn end_hint<T>(&mut self, label: impl Into<Label>, length: Length) -> Result<(), Self::Error> {
        self.end::<T>(label, Kind::Hint, length)
    }

    fn begin_challenge<T>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.begin::<T>(label, Kind::Challenge, length)
    }

    fn end_challenge<T>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.end::<T>(label, Kind::Challenge, length)
    }
}
