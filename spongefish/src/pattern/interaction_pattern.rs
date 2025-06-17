use core::fmt::Display;

use thiserror::Error;

use super::{interaction::Hierarchy, Interaction, Kind};

/// Abstract transcript containing prover-verifier interactions
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct InteractionPattern {
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

impl InteractionPattern {
    pub fn new(interactions: Vec<Interaction>) -> Result<Self, TranscriptError> {
        let result = Self { interactions };
        result.validate()?;
        Ok(result)
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
    // TODO: A more neutral implementation would use ASN.1 DER.
    #[must_use]
    pub fn pattern_hash(&self) -> [u8; 32] {
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
    /// - Matching [`InteractionHierarchy::Begin`] and [`InteractionHierarchy::End`] interactions
    ///   creating a nested hierarchy.
    /// - Nested interactions are the same [`InteractionKind`] as the last [`InteractionHierarchy::Begin`] interaction, except for [`InteractionKind::Protocol`] which can contain any [`InteractionKind`].
    fn validate(&self) -> Result<(), TranscriptError> {
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
                    let Some((begin_position, begin)) = stack.last().copied() else {
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
}

/// Creates a human readable representation of the transcript.
///
/// When called in alternate mode `{:#}` it will be a stable format suitable as domain separator.
impl Display for InteractionPattern {
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
    use crate::pattern::Length;

    #[test]
    fn test_pattern_hash() {
        let transcript = InteractionPattern::new(vec![
            Interaction::new::<usize>(Hierarchy::Begin, Kind::Protocol, "test", Length::None),
            Interaction::new::<Vec<f64>>(
                Hierarchy::Atomic,
                Kind::Message,
                "test-message",
                Length::Scalar,
            ),
            Interaction::new::<usize>(Hierarchy::End, Kind::Protocol, "test", Length::None),
        ])
        .unwrap();

        let result = format!("{transcript:#}");
        let expected = r"Spongefish Transcript (3 interactions)
0 Begin Protocol 4 test None
1   Atomic Message 12 test-message Scalar
2 End Protocol 4 test None
";
        assert_eq!(result, expected);

        let result = transcript.pattern_hash();
        assert_eq!(
            hex::encode(result),
            "33daf542c95b80a2b01be277d9d0f9b6d5bee823c5c3a0dcca71e614a5a783e3"
        );
    }
}
