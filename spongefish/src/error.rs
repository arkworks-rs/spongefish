use core::fmt::Display;

/// An error signaling that verification failed.
#[derive(Debug, Copy, Clone, Default)]
pub struct VerificationError;

/// A [`Result`] wrapper that can either return `T` or a [`VerificationError`].
pub type VerificationResult<T> = Result<T, VerificationError>;

impl Display for VerificationError {
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
