use core::fmt::Display;
use std::{fmt::Write, result, str::FromStr};

use thiserror::Error;

use super::{interaction::InteractionHierarchy, Interaction, InteractionKind};

/// Abstract transcript containing prover-verifier interactions
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct TranscriptPattern {
    interactions: Vec<Interaction>,
}

/// Errors when validating a transcript.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Error)]
pub enum TranscriptError {
    #[error("Missing Begin for {end} at {position}")]
    MissingBegin {
        position: usize,
        end: Box<Interaction>,
    },
    #[error(
        "Invalid kind {interaction} at {interaction_position} for {begin} at {begin_position}"
    )]
    InvalidKind {
        begin_position: usize,
        begin: Box<Interaction>,
        interaction_position: usize,
        interaction: Box<Interaction>,
    },
    #[error("Mismatch {begin} at {begin_position} for {end} at {end_position}")]
    MismatchedBeginEnd {
        begin_position: usize,
        begin: Box<Interaction>,
        end_position: usize,
        end: Box<Interaction>,
    },
    #[error("Missing End for {begin} at {position}")]
    MissingEnd {
        position: usize,
        begin: Box<Interaction>,
    },
}

impl TranscriptPattern {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // False positive
    pub fn interactions(&self) -> &[Interaction] {
        &self.interactions
    }

    /// Generate a stable readble string for the transcript useful as domain separator.
    #[must_use]
    pub fn domain_separator(&self) -> String {
        let mut result = String::new();
        // Use Display in `alternate` mode.
        // Writing to String is invalible.
        write!(&mut result, "{self:#}").unwrap();
        result
    }

    /// Validate the transcript.
    ///
    /// A valid transcript has:
    ///
    /// - Matching [`InteractionHierachy::Begin`] and [`InteractionHierachy::End`] interactions
    ///   creating a nested hierarchy.
    /// - Nested interactions are the same [`InteractionKind`] as the last [`InteractionHierachy::Begin`] interaction, except for [`InteractionKind::Protocol`] which can contain any [`InteractionKind`].
    pub fn validate(&self) -> Result<(), TranscriptError> {
        let mut stack = Vec::new();
        for (position, &interaction) in self.interactions.iter().enumerate() {
            match interaction.hierarchy() {
                InteractionHierarchy::Begin => stack.push((position, interaction)),
                InteractionHierarchy::End => {
                    let Some((position, begin)) = stack.pop() else {
                        return Err(TranscriptError::MissingBegin {
                            position,
                            end: Box::new(interaction),
                        });
                    };
                    let expected = interaction.as_begin();
                    if begin != expected {
                        return Err(TranscriptError::MismatchedBeginEnd {
                            begin_position: position,
                            begin: Box::new(begin),
                            end_position: self.interactions.len(),
                            end: Box::new(interaction),
                        });
                    }
                }
                InteractionHierarchy::Atomic => {
                    let Some((begin_position, begin)) = stack.pop() else {
                        continue;
                    };
                    if begin.kind() != InteractionKind::Protocol
                        && begin.kind() != interaction.kind()
                    {
                        return Err(TranscriptError::InvalidKind {
                            begin_position,
                            begin: Box::new(begin),
                            interaction_position: position,
                            interaction: Box::new(interaction),
                        });
                    }
                }
            }
        }
        if let Some((position, begin)) = stack.pop() {
            return Err(TranscriptError::MissingEnd {
                position,
                begin: Box::new(begin),
            });
        }
        Ok(())
    }

    pub(super) fn push(&mut self, interaction: Interaction) -> Result<(), TranscriptError> {
        if let Some((begin_position, begin)) = self.last_open_begin() {
            // Check if the new interaction is of a permissible kind.
            if begin.kind() != InteractionKind::Protocol && begin.kind() != interaction.kind() {
                return Err(TranscriptError::InvalidKind {
                    begin_position,
                    begin: Box::new(begin),
                    interaction_position: self.interactions.len(),
                    interaction: Box::new(interaction),
                });
            }
            // Check if it is a matching End to the current Begin
            if interaction.hierarchy() == InteractionHierarchy::End
                && begin != interaction.as_begin()
            {
                return Err(TranscriptError::MismatchedBeginEnd {
                    begin_position,
                    begin: Box::new(begin),
                    end_position: self.interactions.len(),
                    end: Box::new(interaction),
                });
            }
        } else {
            // No unclosed Begin interaction. Make sure this is not an end.
            if interaction.hierarchy() == InteractionHierarchy::End {
                return Err(TranscriptError::MissingBegin {
                    position: self.interactions.len(),
                    end: Box::new(interaction),
                });
            }
        }

        // All good, append
        self.interactions.push(interaction);
        Ok(())
    }

    /// Return the last unclosed BEGIN interaction.
    fn last_open_begin(&self) -> Option<(usize, Interaction)> {
        // Reverse search to find matching begin
        let mut stack = 0;
        for (position, &interaction) in self.interactions.iter().rev().enumerate() {
            match interaction.hierarchy() {
                InteractionHierarchy::End => stack += 1,
                InteractionHierarchy::Begin => {
                    if stack == 0 {
                        return Some((position, interaction));
                    }
                    stack -= 1;
                }
                _ => {}
            }
        }
        None
    }
}

/// Creates a human readable representation of the transcript.
///
/// When called in alternate mode `{:#}` it will be a stable format suitable as domain separator.
impl Display for TranscriptPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut indentation = 0;
        // Write the total interactions up front so no prefix string can be a valid domain separator.
        writeln!(
            f,
            "Spongefish Transcript ({} interactions)",
            self.interactions.len()
        )?;
        for (position, interaction) in self.interactions.iter().enumerate() {
            write!(f, "{position:>4} ")?;
            if interaction.hierarchy() == InteractionHierarchy::End {
                indentation -= 1;
            }
            for _ in 0..indentation {
                write!(f, "  ")?;
            }
            writeln!(f, "{interaction}")?;
            if interaction.hierarchy() == InteractionHierarchy::Begin {
                indentation += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size() {
        dbg!(size_of::<Interaction>());
        dbg!(size_of::<TranscriptError>());
    }
}
