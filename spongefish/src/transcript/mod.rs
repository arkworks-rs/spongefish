//! Abstract transcripts for interactive protocols.

mod interaction;
mod pattern_state;
mod transcript_pattern;
mod transcript_player;

pub use self::{
    interaction::{Hierarchy, Interaction, Kind, Label, Length},
    pattern_state::PatternState,
    transcript_pattern::{InteractionPattern, TranscriptError},
    transcript_player::TranscriptPlayer,
};

/// Trait for objects that implement hierarchy operations.
///
/// It does not offer any [`Kind::Atomic`] operations, these need to be implemented specifically.
pub trait Pattern {
    /// End a transcript without finalizing it.
    ///
    /// # Panics
    ///
    /// Panics only if the interaction is already finalized or aborted.
    fn abort(&mut self);

    /// Begin of a group of interactions.
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length);

    /// End of a group of interactions.
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length);

    /// Begin of a subprotocol.
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn begin_protocol<T: ?Sized>(&mut self, label: Label) {
        self.begin::<T>(label.into(), Kind::Protocol, Length::None);
    }

    /// End of a subprotocol.
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn end_protocol<T: ?Sized>(&mut self, label: Label) {
        self.end::<T>(label, Kind::Protocol, Length::None);
    }

    /// Begin of a public message interaction.
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn begin_public<T: ?Sized>(&mut self, label: Label, length: Length) {
        self.begin::<T>(label, Kind::Public, length);
    }

    /// End of a public message interaction.
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn end_public<T: ?Sized>(&mut self, label: Label, length: Length) {
        self.end::<T>(label, Kind::Public, length);
    }

    /// Begin of a message interaction.
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn begin_message<T: ?Sized>(&mut self, label: Label, length: Length) {
        self.begin::<T>(label, Kind::Message, length);
    }

    /// End of a message interaction.
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn end_message<T: ?Sized>(&mut self, label: Label, length: Length) {
        self.end::<T>(label, Kind::Message, length);
    }

    /// Begin of a hint interaction.
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn begin_hint<T: ?Sized>(&mut self, label: Label, length: Length) {
        self.begin::<T>(label, Kind::Hint, length);
    }

    /// End of a hint interaction..
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn end_hint<T: ?Sized>(&mut self, label: Label, length: Length) {
        self.end::<T>(label, Kind::Hint, length);
    }

    /// Begin of a challenge interaction..
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn begin_challenge<T: ?Sized>(&mut self, label: Label, length: Length) {
        self.begin::<T>(label, Kind::Challenge, length);
    }

    /// End of a challenge interaction..
    ///
    /// # Panics
    ///
    /// Panics if the interaction violates interaction pattern consistency rules.
    fn end_challenge<T: ?Sized>(&mut self, label: Label, length: Length) {
        self.end::<T>(label, Kind::Challenge, length);
    }
}

/// Aliases offered for convenience.
pub use Pattern as Common;
/// Aliases offered for convenience.
pub use Pattern as Verifier;
/// Aliases offered for convenience.
pub use Pattern as Prover;
