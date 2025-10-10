/// The [`spongefish`] package has two types of errors:
/// [`DomainSeparatorMismatch`], which is the error exposed in the low-level interface for bytes and native elements,
/// which arises whenever the domain separator specified and the domain separator executed mismatch.
/// [`ProofError`], which is the error exposed to high-level interfaces dealing with structured types and
/// for end-user applications.
/// Three types of errors can happen when dealing with [`ProofError`]:
///
/// - Serialization/Deseralization errors ([`ProofError::SerializationError`]):
///   This includes all potential problems when extracting a particular type from sequences of bytes.
///
/// - Invalid Proof format ([`ProofError::InvalidIO`]):
///   At a higher level, a proof object have to respect the same length and the same types as the protocol description.
///   This error is a wrapper under the [`DomainSeparatorMismatch`] and provides convenient dereference/conversion implementations for
///   moving from/to an [`DomainSeparatorMismatch`].
///
/// - Invalid Proof:
///   An error to signal that the verification equation has failed. Destined for end users.
///
/// A [`core::Result::Result`] wrapper called [`ProofResult`] (having error fixed to [`ProofError`]) is also provided.
use std::{borrow::Borrow, error::Error, fmt::Display};

/// Signals a domain separator is inconsistent with the description provided.
#[derive(Debug, Clone)]
pub struct DomainSeparatorMismatch(String);

/// An error happened when creating or verifying a proof.
#[derive(Debug, Clone)]
pub enum ProofError {
    /// Signals the verification equation has failed.
    InvalidProof,
    /// The domain separator specified mismatches the protocol execution.
    InvalidDomainSeparator(DomainSeparatorMismatch),
    /// Serialization/Deserialization led to errors.
    SerializationError,
}

/// The result type when trying to prove or verify a proof using Fiat-Shamir.
pub type ProofResult<T> = Result<T, ProofError>;

impl Display for DomainSeparatorMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationError => write!(f, "Serialization Error"),
            Self::InvalidDomainSeparator(e) => e.fmt(f),
            Self::InvalidProof => write!(f, "Invalid proof"),
        }
    }
}

impl Error for DomainSeparatorMismatch {}
impl Error for ProofError {}

impl From<&str> for DomainSeparatorMismatch {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl From<String> for DomainSeparatorMismatch {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl<B: Borrow<DomainSeparatorMismatch>> From<B> for ProofError {
    fn from(value: B) -> Self {
        Self::InvalidDomainSeparator(value.borrow().clone())
    }
}

impl From<std::io::Error> for DomainSeparatorMismatch {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}
