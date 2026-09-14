use core::fmt::Display;

/// An error signaling that verification failed.
#[derive(Debug, Copy, Clone, Default)]
pub struct VerificationError;

impl Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Invalid proof")
    }
}

impl core::error::Error for VerificationError {}
