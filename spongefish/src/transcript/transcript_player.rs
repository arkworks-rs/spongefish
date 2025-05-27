use std::sync::Arc;

use thiserror::Error;

use super::{Interaction, Transcript, TranscriptPattern};

/// Play back a transcript and make sure all interactions match up.
///
/// # Panics
///
/// Panics on [`Drop`] if there are unfinished interactions. Please use
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TranscriptPlayer {
    /// Shared reference to the transcript.
    pattern: Arc<TranscriptPattern>,
    /// Current position in the interaction pattern.
    position: usize,
    /// Wheter the transcript playback has been finalized.
    finalized: bool,
}

/// Errors when using a transcript
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Error)]
pub enum InteractionError {
    #[error("Expected {expected} at {position}, got {got}")]
    UnexpectedInteraction {
        position: usize,
        got: Interaction,
        expected: Interaction,
    },
    #[error("Expected {expected} at {position}, got nothing")]
    MissingInteraction {
        position: usize,
        expected: Interaction,
    },
}

impl TranscriptPlayer {
    #[must_use]
    pub const fn new(pattern: Arc<TranscriptPattern>) -> Self {
        Self {
            pattern,
            position: 0,
            finalized: false,
        }
    }

    /// Finalize the sequence of interactions. Returns an error if there
    /// are unfinished interactions.
    pub fn finalize(mut self) -> Result<(), InteractionError> {
        assert!(!self.finalized);
        assert!(self.position <= self.pattern.interactions().len());
        if self.position < self.pattern.interactions().len() {
            return Err(InteractionError::MissingInteraction {
                position: self.position,
                expected: self.pattern.interactions()[self.position].clone(),
            });
        }
        self.finalized = true;
        Ok(())
    }

    pub fn interact(&mut self, interaction: Interaction) -> Result<(), InteractionError> {
        assert!(!self.finalized, "Transcript is already finalized."); // Or should this be an error?
        let Some(expected) = self.pattern.interactions().get(self.position) else {
            return Err(InteractionError::MissingInteraction {
                position: self.position,
                expected: interaction,
            });
        };
        if expected != &interaction {
            return Err(InteractionError::UnexpectedInteraction {
                position: self.position,
                got: interaction,
                expected: expected.clone(),
            });
        }
        self.position += 1;
        Ok(())
    }
}

impl Drop for TranscriptPlayer {
    fn drop(&mut self) {
        if !self.finalized {
            panic!("Dropped unfinalized transcript.");
        }
    }
}
