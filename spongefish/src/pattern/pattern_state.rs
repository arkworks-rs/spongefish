use std::marker::PhantomData;

use super::{Hierarchy, Interaction, InteractionPattern, Kind, Label, Length};
use crate::Unit;

/// Records an interaction pattern.
///
/// # Panics
///
/// Panics on [`Drop`] if there are unfinished interactions.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct PatternState<U = u8>
where
    U: Unit,
{
    /// Recorded interactions.
    interactions: Vec<Interaction>,
    /// Whether the transcript playback has been finalized.
    finalized: bool,
    _unit: PhantomData<U>,
}

impl<U> PatternState<U>
where
    U: Unit,
{
    #[must_use]
    pub const fn new() -> Self {
        Self {
            interactions: Vec::new(),
            finalized: false,
            _unit: PhantomData,
        }
    }

    #[must_use]
    pub fn finalize(self) -> InteractionPattern {
        assert!(!self.finalized, "Transcript is already finalized.");
        match InteractionPattern::new(self.interactions) {
            Ok(transcript) => transcript,
            Err(e) => panic!("Error validating interaction pattern: {e}"),
        }
    }

    /// Add a new interaction to the pattern.
    ///
    /// # Panics
    ///
    /// Panics if
    /// - the interaction does not match the parent kind and
    ///   the parent kind is not [`Kind::Protocol`],
    /// - the it is an [`Hierarchy::End`], but there is either no
    ///   [`Hierarchy::Begin`] or it does not match the end.being
    pub fn interact(&mut self, interaction: Interaction) {
        assert!(!self.finalized, "Transcript is already finalized.");
        if let Some(begin) = self.last_open_begin() {
            // Check if the new interaction is of a permissible kind.
            assert!(
                begin.kind() == Kind::Protocol || begin.kind() == interaction.kind(),
                "Invalid interaction kind: expected {}, got {}",
                begin.kind(),
                interaction.kind()
            );
            // Check if it is a matching End to the current Begin
            assert!(
                interaction.hierarchy() != Hierarchy::End || interaction.closes(begin),
                "Mismatched begin and end: {begin}, {interaction}"
            );
        } else {
            // No unclosed Begin interaction. Make sure this is not an end.
            assert!(
                interaction.hierarchy() != Hierarchy::End,
                "Missing begin for {interaction}"
            );
        }

        // All good, append
        self.interactions.push(interaction);
    }

    /// Return the last unclosed [`Hierarchy::Begin`] interaction.
    fn last_open_begin(&self) -> Option<&Interaction> {
        // Reverse search to find matching begin
        let mut stack = 0;
        for interaction in self.interactions.iter().rev() {
            match interaction.hierarchy() {
                Hierarchy::End => stack += 1,
                Hierarchy::Begin => {
                    if stack == 0 {
                        return Some(interaction);
                    }
                    stack -= 1;
                }
                _ => {}
            }
        }
        None
    }
}

impl<U> super::Pattern for PatternState<U>
where
    U: Unit,
{
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
