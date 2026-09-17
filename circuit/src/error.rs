//! The error of [`PermutationRelation::compile`][crate::PermutationRelation::compile].

use alloc::string::String;
use core::fmt;

/// A relation that does not describe a valid instance.
///
/// Raised by [`PermutationRelation::compile`][crate::PermutationRelation::compile],
/// the one gate through which a relation becomes a
/// [`PermutationInstance`][crate::PermutationInstance]. Building a relation
/// never fails; the checks run here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidRelation {
    message: String,
}

impl InvalidRelation {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// What was wrong with the relation.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for InvalidRelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid relation: {}", self.message)
    }
}

impl core::error::Error for InvalidRelation {}
