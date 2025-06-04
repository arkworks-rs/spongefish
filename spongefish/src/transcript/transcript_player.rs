use std::sync::Arc;

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

/// # Panics
///
/// Panics if dropped without finalizing or aborting.
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
    ///
    /// # Panics
    ///
    /// Panics if already finalized or aborted.
    pub fn abort(&mut self) {
        assert!(!self.finalized, "Transcript is already finalized.");
        self.finalized = true;
    }

    /// Finalize the sequence of interactions. Returns an error if there
    /// are unfinished interactions.
    ///
    /// # Panics
    ///
    /// Panics if the transcript is already finalized or if there are expected interactions left.
    pub fn finalize(mut self) {
        assert!(self.position <= self.pattern.interactions().len());
        assert!(!self.finalized, "Transcript is already finalized.");
        assert!(
            self.position >= self.pattern.interactions().len(),
            "Transcript not finished, expecting {}",
            self.pattern.interactions()[self.position]
        );
        self.finalized = true;
    }

    /// Play the next interaction in the pattern.
    ///
    /// # Panics
    ///
    /// Panics if the transcript is already finalized or if the interaction does not match the expected one.
    pub fn interact(&mut self, interaction: Interaction) {
        assert!(!self.finalized, "Transcript is already finalized.");
        let Some(expected) = self.pattern.interactions().get(self.position) else {
            self.finalized = true;
            panic!("Received interaction, but no more expected interactions: {interaction}");
        };
        if expected != &interaction {
            self.finalized = true;
            panic!("Received interaction {interaction}, but expected {expected}");
        }
        self.position += 1;
    }
}

impl Drop for TranscriptPlayer {
    fn drop(&mut self) {
        assert!(self.finalized, "Dropped unfinalized transcript.");
    }
}
