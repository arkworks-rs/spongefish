use core::{any::type_name, fmt::Display};

/// A single abstract prover-verifier interaction
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Interaction {
    /// The kind of interaction.
    kind: InteractionKind,
    /// A label identifying the purpose of the value.
    label: &'static str,
    /// The Rust name of the type of the value.
    ///
    /// We use [`core::any::type_name`] here intead of [`core::any::TypeID`] since the latter
    /// only supports types with a `'static` lifetime. The downside of `type_name` is that
    /// it is slightly less precise in that it can create more type collisions. But this is
    /// acceptable here as it only serves as an additional check and as debug information.
    type_name: &'static str,
    /// Length of the value.
    length: Length,
}

/// Kinds of prover-verifier interactions
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum InteractionKind {
    /// A message send in-band from prover to verifier.
    Message,
    /// A hint send out-of-band from prover to verifier.
    Hint,
    /// A challenge derived from the transform.
    Challenge,
    /// The start of a sub-protocol
    Begin,
    /// The end of a sub-protocol
    End,
}

/// Length of values involved in interactions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Length {
    None,
    Scalar,
    Fixed(usize),
    Dynamic,
}

impl Interaction {
    #[must_use]
    pub fn new<T>(kind: InteractionKind, label: &'static str, length: Length) -> Self {
        Self {
            kind,
            label,
            type_name: type_name::<T>(),
            length,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> InteractionKind {
        self.kind
    }

    /// If it is an `InteractionKind::End`, return the corresponding `InteractionKind::Begin`
    #[must_use]
    pub(super) fn as_begin(self) -> Self {
        assert_eq!(self.kind, InteractionKind::End);
        Self {
            kind: InteractionKind::Begin,
            ..self
        }
    }
}

impl Display for Interaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.kind, self.label, self.type_name)
    }
}

impl Display for InteractionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message => write!(f, "MESSAGE"),
            Self::Hint => write!(f, "HINT"),
            Self::Challenge => write!(f, "CHALLENGE"),
            Self::Begin => write!(f, "BEGIN"),
            Self::End => write!(f, "END"),
        }
    }
}
