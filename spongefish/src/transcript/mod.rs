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

/// Trait for objects that implement hierarchy operations.
///
/// It does not offer any [`Kind::Atomic`] operations, these need to be implemented specifically.
pub trait Transcript {
    type Error: Error;

    /// Begin of a group of interactions.
    fn begin<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error>;

    /// End of a group of interactions.
    fn end<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error>;

    /// Begin of a subprotocol.
    fn begin_protocol<T: ?Sized>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        self.begin::<T>(label.into(), Kind::Protocol, Length::None)
    }

    /// End of a subprotocol.
    fn end_protocol<T: ?Sized>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        self.end::<T>(label, Kind::Protocol, Length::None)
    }

    /// Begin of a public message interaction.
    fn begin_public<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.begin::<T>(label, Kind::Public, length)
    }

    /// End of a public message interaction.
    fn end_public<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.end::<T>(label, Kind::Public, length)
    }
    /// Begin of a message interaction.
    fn begin_message<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.begin::<T>(label, Kind::Message, length)
    }

    /// End of a message interaction.
    fn end_message<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.end::<T>(label, Kind::Message, length)
    }

    /// Begin of a hint interaction.
    fn begin_hint<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.begin::<T>(label, Kind::Hint, length)
    }

    /// End of a hint interaction..
    fn end_hint<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.end::<T>(label, Kind::Hint, length)
    }

    /// Begin of a challenge interaction..
    fn begin_challenge<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.begin::<T>(label, Kind::Challenge, length)
    }

    /// End of a challenge interaction..
    fn end_challenge<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.end::<T>(label, Kind::Challenge, length)
    }
}
