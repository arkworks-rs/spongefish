//! Verification errors and result type.

/// Verification failed.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerificationError;

/// Result type for verification operations.
pub type VerificationResult<T> = Result<T, VerificationError>;

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Invalid proof")
    }
}

impl core::ops::Deref for VerificationError {
    type Target = VerificationResult<()>;

    fn deref(&self) -> &Self::Target {
        &Err(Self)
    }
}

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
impl std::error::Error for VerificationError {}
