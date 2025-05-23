use core::fmt::Display;
use std::fmt::Write as _;

use thiserror::Error;

use super::{interaction::Hierarchy, Interaction, Kind};

/// Abstract transcript containing prover-verifier interactions
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct TranscriptPattern {
    interactions: Vec<Interaction>,
}

/// Errors when validating a transcript.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Error)]
pub enum TranscriptError {
    #[error("Missing Begin for {end} at {position}")]
    MissingBegin { position: usize, end: Interaction },
    #[error(
        "Invalid kind {interaction} at {interaction_position} for {begin} at {begin_position}"
    )]
    InvalidKind {
        begin_position: usize,
        begin: Interaction,
        interaction_position: usize,
        interaction: Interaction,
    },
    #[error("Mismatch {begin} at {begin_position} for {end} at {end_position}")]
    MismatchedBeginEnd {
        begin_position: usize,
        begin: Interaction,
        end_position: usize,
        end: Interaction,
    },
    #[error("Missing End for {begin} at {position}")]
    MissingEnd { position: usize, begin: Interaction },
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

    /// Generate a unique identifier for the protocol.
    ///
    /// It is created by taking the SHA3 hash of a stable unambiguous
    /// string representation of the transcript interactions.
    #[must_use]
    pub fn domain_separator(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        // Use Display in `alternate` mode for stable unambiguous representation.
        hasher.update(format!("{self:#}").as_bytes());
        let result = hasher.finalize();
        result.into()
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
        for (position, interaction) in self.interactions.iter().enumerate() {
            match interaction.hierarchy() {
                Hierarchy::Begin => stack.push((position, interaction)),
                Hierarchy::End => {
                    let Some((position, begin)) = stack.pop() else {
                        return Err(TranscriptError::MissingBegin {
                            position,
                            end: interaction.clone(),
                        });
                    };
                    if !interaction.closes(begin) {
                        return Err(TranscriptError::MismatchedBeginEnd {
                            begin_position: position,
                            begin: begin.clone(),
                            end_position: self.interactions.len(),
                            end: interaction.clone(),
                        });
                    }
                }
                Hierarchy::Atomic => {
                    let Some((begin_position, begin)) = stack.pop() else {
                        continue;
                    };
                    if begin.kind() != Kind::Protocol && begin.kind() != interaction.kind() {
                        return Err(TranscriptError::InvalidKind {
                            begin_position,
                            begin: begin.clone(),
                            interaction_position: position,
                            interaction: interaction.clone(),
                        });
                    }
                }
            }
        }
        if let Some((position, begin)) = stack.pop() {
            return Err(TranscriptError::MissingEnd {
                position,
                begin: begin.clone(),
            });
        }
        Ok(())
    }

    pub(super) fn push(&mut self, interaction: Interaction) -> Result<(), TranscriptError> {
        if let Some((begin_position, begin)) = self.last_open_begin() {
            // Check if the new interaction is of a permissible kind.
            if begin.kind() != Kind::Protocol && begin.kind() != interaction.kind() {
                return Err(TranscriptError::InvalidKind {
                    begin_position,
                    begin: begin.clone(),
                    interaction_position: self.interactions.len(),
                    interaction: interaction.clone(),
                });
            }
            // Check if it is a matching End to the current Begin
            if interaction.hierarchy() == Hierarchy::End && !interaction.closes(begin) {
                return Err(TranscriptError::MismatchedBeginEnd {
                    begin_position,
                    begin: begin.clone(),
                    end_position: self.interactions.len(),
                    end: interaction.clone(),
                });
            }
        } else {
            // No unclosed Begin interaction. Make sure this is not an end.
            if interaction.hierarchy() == Hierarchy::End {
                return Err(TranscriptError::MissingBegin {
                    position: self.interactions.len(),
                    end: interaction.clone(),
                });
            }
        }

        // All good, append
        self.interactions.push(interaction);
        Ok(())
    }

    /// Return the last unclosed BEGIN interaction.
    fn last_open_begin(&self) -> Option<(usize, &Interaction)> {
        // Reverse search to find matching begin
        let mut stack = 0;
        for (position, interaction) in self.interactions.iter().rev().enumerate() {
            match interaction.hierarchy() {
                Hierarchy::End => stack += 1,
                Hierarchy::Begin => {
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
        // Write the total interactions up front so no prefix string can be a valid domain separator.
        let length = self.interactions.len();
        let width = length.saturating_sub(1).to_string().len();
        writeln!(f, "Spongefish Transcript ({length} interactions)")?;
        let mut indentation = 0;
        for (position, interaction) in self.interactions.iter().enumerate() {
            write!(f, "{position:0>width$} ")?;
            if interaction.hierarchy() == Hierarchy::End {
                indentation -= 1;
            }
            for _ in 0..indentation {
                write!(f, "  ")?;
            }
            if f.alternate() {
                writeln!(f, "{interaction:#}")?;
            } else {
                writeln!(f, "{interaction}")?;
            }
            if interaction.hierarchy() == Hierarchy::Begin {
                indentation += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::{self, Length};

    #[test]
    fn test_size() {
        dbg!(size_of::<TranscriptError>());
        assert!(size_of::<TranscriptError>() < 170);
    }

    #[test]
    fn test_domain_separator() {
        let mut transcript = TranscriptPattern::new();

        transcript
            .push(Interaction::new::<usize>(
                Hierarchy::Begin,
                Kind::Protocol,
                "test",
                Length::None,
            ))
            .unwrap();
        transcript
            .push(Interaction::new::<Vec<f64>>(
                Hierarchy::Atomic,
                Kind::Message,
                "test-message",
                Length::Scalar,
            ))
            .unwrap();
        transcript
            .push(Interaction::new::<usize>(
                Hierarchy::End,
                Kind::Protocol,
                "test",
                Length::None,
            ))
            .unwrap();
        let result = format!("{transcript:#}");
        let expected = r"Spongefish Transcript (3 interactions)
0 Begin Protocol 4test None
1   Atomic Message 12test-message Scalar
2 End Protocol 4test None
";
        assert_eq!(result, expected);

        let result = transcript.domain_separator();
        assert_eq!(hex::encode(result), "asd");
    }
}
