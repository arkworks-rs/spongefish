use std::marker::PhantomData;

use super::{Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, TranscriptError};
use crate::{codecs::unit, Unit};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PatternState<U = u8>
where
    U: Unit,
{
    interactions: Vec<Interaction>,
    _unit: PhantomData<U>,
}

impl<U> PatternState<U>
where
    U: Unit,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            interactions: Vec::new(),
            _unit: PhantomData,
        }
    }

    pub fn finalize(self) -> InteractionPattern {
        match InteractionPattern::new(self.interactions) {
            Ok(transcript) => transcript,
            Err(e) => panic!("Error validating interaction pattern: {e}"),
        }
    }

    pub fn interact(&mut self, interaction: Interaction) {
        if let Some(begin) = self.last_open_begin() {
            // Check if the new interaction is of a permissible kind.
            if begin.kind() != Kind::Protocol && begin.kind() != interaction.kind() {
                panic!(
                    "Invalid interaction kind: expected {}, got {}",
                    begin.kind(),
                    interaction.kind()
                );
            }
            // Check if it is a matching End to the current Begin
            if interaction.hierarchy() == Hierarchy::End && !interaction.closes(begin) {
                panic!("Mismatched begin and end: {begin}, {interaction}");
            }
        } else {
            // No unclosed Begin interaction. Make sure this is not an end.
            if interaction.hierarchy() == Hierarchy::End {
                panic!("Missing begin for {interaction}");
            }
        }

        // All good, append
        self.interactions.push(interaction);
    }

    /// Return the last unclosed BEGIN interaction.
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

impl<U> Default for PatternState<U>
where
    U: Unit,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<U> super::Pattern for PatternState<U>
where
    U: Unit,
{
    fn abort(&mut self) {
        todo!()
    }

    fn begin<T: ?Sized>(&mut self, label: impl Into<Label>, kind: Kind, length: Length) {
        self.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length));
    }

    fn end<T: ?Sized>(&mut self, label: impl Into<Label>, kind: Kind, length: Length) {
        self.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length));
    }
}

impl<U> unit::Pattern for PatternState<U>
where
    U: Unit,
{
    type Unit = U;

    fn ratchet(&mut self) {
        self.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            "ratchet",
            Length::Scalar,
        ));
    }

    fn public_unit(&mut self, label: impl Into<Label>) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Scalar,
        ));
    }

    fn public_units(&mut self, label: impl Into<Label>, size: usize) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(size),
        ));
    }

    fn message_unit(&mut self, label: impl Into<Label>) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Scalar,
        ));
    }

    fn message_units(&mut self, label: impl Into<Label>, size: usize) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(size),
        ));
    }

    fn challenge_unit(&mut self, label: impl Into<Label>) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Scalar,
        ));
    }

    fn challenge_units(&mut self, label: impl Into<Label>, size: usize) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(size),
        ));
    }

    fn hint_bytes(&mut self, label: impl Into<Label>, size: usize) {
        self.interact(Interaction::new::<[u8]>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Fixed(size),
        ));
    }

    fn hint_bytes_dynamic(&mut self, label: impl Into<Label>) {
        self.interact(Interaction::new::<[u8]>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ));
    }
}
