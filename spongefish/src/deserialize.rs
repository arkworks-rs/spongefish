//! Prover-message deserialization bridging NARG codecs.

use crate::NargDeserialize;
use crate::error::{VerificationError, VerificationResult};

/// Reconstruct a typed value from a byte buffer.
///
/// This is the inverse of [`Encoding`][crate::Encoding]: given the serialized bytes of a
/// prover message, produce the original value.  Blanket-implemented for
/// every type that has [`NargDeserialize`].
pub trait Deserialize: NargDeserialize {
    fn deserialize(buf: &mut &[u8]) -> VerificationResult<Self>;
}

impl<T: NargDeserialize> Deserialize for T {
    fn deserialize(buf: &mut &[u8]) -> VerificationResult<Self> {
        T::deserialize_from_narg(buf).map_err(|_| VerificationError)
    }
}
