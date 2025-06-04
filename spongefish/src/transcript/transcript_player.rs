use std::sync::Arc;

use thiserror::Error;

use super::{Interaction, InteractionPattern};

/// Play back a transcript and make sure all interactions match up.
///
/// # Panics
///
/// Panics on [`Drop`] if there are unfinished interactions. Please use
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TranscriptPlayer {
    /// Shared reference to the transcript.
    pattern: Arc<InteractionPattern>,
    /// Current position in the interaction pattern.
    position: usize,
    /// Whether the transcript playback has been finalized.
    finalized: bool,
}

/// Errors when using a transcript
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Error)]
pub enum InteractionError {
    #[error("At {position} expected {expected}, got {got}")]
    UnexpectedInteraction {
        position: usize,
        got: Interaction,
        expected: Interaction,
    },
    #[error("At {position} expected {expected}, got nothing")]
    MissingInteraction {
        position: usize,
        expected: Interaction,
    },
}

impl TranscriptPlayer {
    #[must_use]
    pub const fn new(pattern: Arc<InteractionPattern>) -> Self {
        Self {
            pattern,
            position: 0,
            finalized: false,
        }
    }

    /// Abort the sequence of interactions.
    ///
    /// This prevents the unfinalized [`TranscriptPlayer`] from panicking on drop.
    pub fn abort(&mut self) {
        assert!(!self.finalized);
        self.finalized = true;
    }

    /// Finalize the sequence of interactions. Returns an error if there
    /// are unfinished interactions.
    pub fn finalize(mut self) -> Result<(), InteractionError> {
        assert!(!self.finalized);
        assert!(self.position <= self.pattern.interactions().len());
        if self.position < self.pattern.interactions().len() {
            self.finalized = true;
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
            self.finalized = true;
            return Err(InteractionError::MissingInteraction {
                position: self.position,
                expected: interaction,
            });
        };
        if expected != &interaction {
            self.finalized = true;
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
        assert!(self.finalized, "Dropped unfinalized transcript.");
    }
}
