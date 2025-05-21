use core::{any::type_name, fmt::Display};

/// A single abstract prover-verifier interaction.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Interaction {
    /// Hierarchical nesting of the interactions.
    hierarchy: InteractionHierarchy,
    /// The kind of interaction.
    kind: InteractionKind,
    /// A label identifying the purpose of the value.
    label: &'static str,
    /// The Rust name of the type of the value.
    ///
    /// We use [`core::any::type_name`] to verify value types intead of [`core::any::TypeID`] since
    /// the latter only supports types with a `'static` lifetime. The downside of `type_name` is
    /// that it is slightly less precise in that it can create more type collisions. But this is
    /// acceptable here as it only serves as an additional check and as debug information.
    type_name: &'static str,
    /// Length of the value.
    length: Length,
}

/// Kinds of prover-verifier interactions
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum InteractionKind {
    /// A protocol containing mixed interactions.
    Protocol,
    /// A message send in-band from prover to verifier.
    Message,
    /// A hint send out-of-band from prover to verifier.
    Hint,
    /// A challenge issued by the verifier.
    Challenge,
}

/// Kinds of prover-verifier interactions
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum InteractionHierarchy {
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
    pub fn new<T>(
        hierarchy: InteractionHierarchy,
        kind: InteractionKind,
        label: &'static str,
        length: Length,
    ) -> Self {
        Self {
            hierarchy,
            kind,
            label,
            type_name: type_name::<T>(),
            length,
        }
    }

    #[must_use]
    pub const fn hierarchy(&self) -> InteractionHierarchy {
        self.hierarchy
    }

    #[must_use]
    pub const fn kind(&self) -> InteractionKind {
        self.kind
    }

    /// If it is an `InteractionHierarchy::End`, return the
    /// corresponding `InteractionHierarchy::Begin`
    #[must_use]
    pub(super) fn as_begin(self) -> Self {
        assert_eq!(self.hierarchy, InteractionHierarchy::End);
        Self {
            hierarchy: InteractionHierarchy::Begin,
            ..self
        }
    }
}

impl Display for Interaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.kind, self.label, self.type_name)
    }
}

impl Display for InteractionHierarchy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Atomic => write!(f, "Atomic"),
            Self::Begin => write!(f, "Begin"),
            Self::End => write!(f, "End"),
        }
    }
}

impl Display for InteractionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol => write!(f, "Protocol"),
            Self::Message => write!(f, "Message"),
            Self::Hint => write!(f, "Hint"),
            Self::Challenge => write!(f, "Challenge"),
        }
    }
}
