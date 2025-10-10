use core::{any::type_name, fmt::Display};

/// A single abstract prover-verifier interaction.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Interaction {
    /// Hierarchical nesting of the interactions.
    hierarchy: Hierarchy,
    /// The kind of interaction.
    kind: Kind,
    /// A label identifying the purpose of the value.
    label: Label,
    /// The Rust name of the type of the value.
    ///
    /// We use [`core::any::type_name`] to verify value types instead of [`core::any::TypeID`] since
    /// the latter only supports types with a `'static` lifetime. The downside of `type_name` is
    /// that it is slightly less precise in that it can create more type collisions. But this is
    /// acceptable here as it only serves as an additional check and as debug information.
    type_name: &'static str,
    /// Length of the value.
    length: Length,
}

/// Labels for interactions.
pub type Label = &'static str;

/// Kinds of prover-verifier interactions
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Kind {
    /// A protocol containing mixed interactions.
    Protocol,
    /// A public message prover and verifier agree on.
    Public,
    /// A message send in-band from prover to verifier.
    Message,
    /// A hint send out-of-band from prover to verifier.
    Hint,
    /// A challenge issued by the verifier.
    Challenge,
}

/// Kinds of prover-verifier interactions
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Hierarchy {
    /// A single interaction.
    Atomic,
    /// Start of a sub-protocol.
    Begin,
    /// End of a sub-protocol.
    End,
}

/// Length of values involved in interactions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Length {
    /// No length information.
    None,
    /// A single value.
    Scalar,
    /// A fixed number of values.
    Fixed(usize),
    /// A dynamic number of values.
    Dynamic,
}

impl Interaction {
    #[must_use]
    pub fn new<T: ?Sized>(hierarchy: Hierarchy, kind: Kind, label: Label, length: Length) -> Self {
        let type_name = type_name::<T>();
        Self {
            hierarchy,
            kind,
            label,
            type_name,
            length,
        }
    }

    #[must_use]
    pub const fn hierarchy(&self) -> Hierarchy {
        self.hierarchy
    }

    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// Returns `true` if this is a `Hierarchy::End` that closes the provided
    /// `Hierarchy::Begin`.
    #[must_use]
    pub(super) fn closes(&self, other: &Self) -> bool {
        self.hierarchy == Hierarchy::End
            && other.hierarchy == Hierarchy::Begin
            && self.kind == other.kind
            && self.label == other.label
            && self.type_name == other.type_name
            && self.length == other.length
    }
}

impl Display for Interaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            // Domain separator mode: stable unambiguous format.
            write!(f, "{} {}", self.hierarchy, self.kind)?;
            // Length prefixed strings for labels to disambiguate
            write!(f, " {} {}", self.label.len(), self.label)?;
            write!(f, " {}", self.length)
            // Leave out type names for domain separators.
        } else {
            write!(
                f,
                "{} {} {} {} {}",
                self.hierarchy, self.kind, self.label, self.length, self.type_name,
            )
        }
    }
}

impl Display for Hierarchy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Atomic => write!(f, "Atomic"),
            Self::Begin => write!(f, "Begin"),
            Self::End => write!(f, "End"),
        }
    }
}

impl Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol => write!(f, "Protocol"),
            Self::Public => write!(f, "Public"),
            Self::Message => write!(f, "Message"),
            Self::Hint => write!(f, "Hint"),
            Self::Challenge => write!(f, "Challenge"),
        }
    }
}

impl Display for Length {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Scalar => write!(f, "Scalar"),
            Self::Fixed(size) => write!(f, "Fixed({size})"),
            Self::Dynamic => write!(f, "Dynamic"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separator() {
        let interaction = Interaction::new::<Vec<f64>>(
            Hierarchy::Atomic,
            Kind::Message,
            "test-message",
            Length::Scalar,
        );
        let result = format!("{interaction:#}");
        let expected = "Atomic Message 12 test-message Scalar";
        assert_eq!(result, expected);
    }
}
