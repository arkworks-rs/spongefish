use thiserror::Error;

use super::{Interaction, Transcript, TranscriptPattern};

pub struct TranscriptPlayer<'a> {
    pattern: &'a TranscriptPattern,
    position: usize,
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

impl<'a> TranscriptPlayer<'a> {
    #[must_use]
    pub const fn new(pattern: &'a TranscriptPattern) -> Self {
        Self {
            pattern,
            position: 0,
        }
    }

    pub fn finalize(&mut self) -> Result<(), InteractionError> {
        assert!(self.position <= self.pattern.interactions().len());
        if self.position < self.pattern.interactions().len() {
            return Err(InteractionError::MissingInteraction {
                position: self.position,
                expected: self.pattern.interactions()[self.position].clone(),
            });
        }
        Ok(())
    }
}

impl Drop for TranscriptPlayer<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.finalize() {
            panic!("Dropped unfinalized transcript: {e}");
        }
    }
}

impl Transcript for TranscriptPlayer<'_> {
    type Error = InteractionError;

    fn interact(&mut self, interaction: Interaction) -> Result<(), InteractionError> {
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
