use alloc::vec::Vec;

use crate::{codecs::Encoding, VerificationResult};

/// Wrapper trait for std::io::Read.
pub trait Serialize {
    fn serialize_into(&self, dst: &mut Vec<u8>);
}

/// Wrapper trait for serialization of prover messages into the proof string.
pub trait Deserialize: Sized {
    fn deserialize_from(buf: &[u8]) -> VerificationResult<Self>;
}

impl<T: Encoding<[u8]>> Serialize for T {
    fn serialize_into(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(self.encode().as_ref());
    }
}

impl Deserialize for Vec<u8> {
    fn deserialize_from(buf: &[u8]) -> VerificationResult<Self> {
        Ok(buf.to_vec())
    }
}
