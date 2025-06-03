use std::io::Write;

use thiserror::Error;

use crate::ensure;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Error)]
pub enum ReadError {
    #[error("Transcript string ended unexpectedly.")]
    UnexpectEndOfTranscript,
    #[error("Invalid data encountered while reading from the transcript.")]
    IvalidData,
}

/// Basic units over which a sponge operates.
///
/// We require the units to have a precise size in memory, to be cloneable,
/// and that we can zeroize them.
pub trait Unit: Clone + Sized + zeroize::Zeroize {
    /// Write a bunch of units in the wire.
    /// The provided writer is infallible so no error should be returned.
    fn write(bunch: &[Self], w: impl Write);

    /// Read a bunch of units from the wire and returns the number of bytes consumed.
    fn read(bytes: &[u8], bunch: &mut [Self]) -> Result<usize, ReadError>;
}

impl Unit for u8 {
    fn write(bunch: &[Self], mut w: impl Write) {
        w.write_all(&bunch).expect("Infallible writer");
    }

    fn read(bytes: &[u8], bunch: &mut [Self]) -> Result<usize, ReadError> {
        ensure!(
            bytes.len() >= bunch.len(),
            ReadError::UnexpectEndOfTranscript
        );
        bunch.copy_from_slice(&bytes[..bunch.len()]);
        Ok(bunch.len())
    }
}
