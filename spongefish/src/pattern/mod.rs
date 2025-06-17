//! Abstract interaction patterns for interactive protocols.

mod interaction;
mod interaction_pattern;
mod pattern_player;
mod pattern_state;

pub use self::{
    interaction::{Hierarchy, Interaction, Kind, Label, Length},
    interaction_pattern::{InteractionPattern, TranscriptError},
    pattern_player::PatternPlayer,
    pattern_state::PatternState,
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
        self.begin::<T>(label, Kind::Protocol, Length::None);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_playback() {
        // Record a new pattern
        let mut pattern = PatternState::<u8>::new();
        pattern.begin_protocol::<()>("Example protocol");
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Scalar,
        ));
        pattern.end_protocol::<()>("Example protocol");
        let pattern = pattern.finalize();

        // Play it back exactly
        let mut playback = PatternPlayer::new(pattern.into());
        playback.begin_protocol::<()>("Example protocol");
        playback.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Scalar,
        ));
        playback.end_protocol::<()>("Example protocol");
        playback.finalize();
    }

    #[test]
    #[should_panic(expected = "Dropped unfinalized transcript.")]
    fn panics_if_playback_not_finalized() {
        let mut pattern = PatternState::<u8>::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Scalar,
        ));
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Scalar,
        ));
    }

    #[test]
    #[should_panic(
        expected = "Mismatched begin and end: Begin Protocol Example protocol None (), End Protocol Invalid example protocol None ()"
    )]
    fn panics_if_record_begin_end_mismatch() {
        let mut pattern = PatternState::<u8>::new();
        pattern.begin_protocol::<()>("Example protocol");
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Scalar,
        ));
        pattern.end_protocol::<()>("Invalid example protocol");
        let _pattern = pattern.finalize();
    }
    #[test]
    #[should_panic(
        expected = "Error validating interaction pattern: Missing End for Begin Protocol Example protocol None () at 0"
    )]
    fn panics_if_record_unmatched_begin() {
        let mut pattern = PatternState::<u8>::new();
        pattern.begin_protocol::<()>("Example protocol");
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Scalar,
        ));
        let _pattern = pattern.finalize();
    }

    #[test]
    #[should_panic(
        expected = "Received interaction Atomic Challenge nonce Scalar f64, but expected Atomic Challenge nonce Scalar u64"
    )]
    fn panics_if_type_mismatch() {
        let mut pattern = PatternState::<u8>::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Scalar,
        ));
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Scalar,
        ));
        playback.finalize();
    }

    #[test]
    #[should_panic(
        expected = "Received interaction Atomic Public nonce Scalar f64, but expected Atomic Message nonce Scalar u64"
    )]
    fn panics_if_kind_mismatch() {
        let mut pattern = PatternState::<u8>::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Message,
            "nonce",
            Length::Scalar,
        ));
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Public,
            "nonce",
            Length::Scalar,
        ));
        playback.finalize();
    }

    #[test]
    #[should_panic(
        expected = "Received interaction Atomic Challenge invalid Scalar f64, but expected Atomic Challenge nonce Scalar u64"
    )]
    fn panics_if_label_mismatch() {
        let mut pattern = PatternState::<u8>::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Scalar,
        ));
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "invalid",
            Length::Scalar,
        ));
        playback.finalize();
    }

    #[test]
    #[should_panic(
        expected = "Received interaction Atomic Challenge nonce Fixed(1) f64, but expected Atomic Challenge nonce Scalar u64"
    )]
    fn panics_if_length_mismatch() {
        let mut pattern = PatternState::<u8>::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Scalar,
        ));
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "nonce",
            Length::Fixed(1),
        ));
        playback.finalize();
    }
}
