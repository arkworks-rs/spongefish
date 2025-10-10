use std::sync::Arc;

use super::{Interaction, InteractionPattern, Kind, Label, Length};
use crate::pattern::Hierarchy;

/// Play back an interaction pattern and make sure all interactions match up.
///
/// # Panics
///
/// Panics on [`Drop`] if there are unfinished interactions.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PatternPlayer {
    /// Shared reference to the transcript.
    pattern: Arc<InteractionPattern>,
    /// Current position in the interaction pattern.
    position: usize,
    /// Whether the transcript playback has been finalized.
    finalized: bool,
}

impl PatternPlayer {
    #[must_use]
    pub const fn new(pattern: Arc<InteractionPattern>) -> Self {
        Self {
            pattern,
            position: 0,
            finalized: false,
        }
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

impl Drop for PatternPlayer {
    fn drop(&mut self) {
        assert!(self.finalized, "Dropped unfinalized transcript.");
    }
}

impl super::Pattern for PatternPlayer {
    fn abort(&mut self) {
        assert!(!self.finalized, "Transcript is already finalized.");
        self.finalized = true;
    }

    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) {
        self.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length));
    }

    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) {
        self.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length));
    }
}
