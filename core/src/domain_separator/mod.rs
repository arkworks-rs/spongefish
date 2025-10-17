/// Proposed alternative domain separator
pub mod pattern;

pub mod safe;

pub use safe::*;
/// SAFE API.
pub mod sho;

/// Traits for domain separator
pub mod traits;

use crate::alloc::string::ToString;
impl From<&str> for DomainSeparatorMismatch {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl From<alloc::string::String> for DomainSeparatorMismatch {
    fn from(s: alloc::string::String) -> Self {
        Self(s)
    }
}

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
impl From<std::io::Error> for DomainSeparatorMismatch {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}

/// Signals a domain separator is inconsistent with the description provided.
#[derive(Debug, Clone)]
pub struct DomainSeparatorMismatch(alloc::string::String);
