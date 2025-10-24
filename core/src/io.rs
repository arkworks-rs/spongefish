use alloc::vec::Vec;

use crate::{codecs::Encoding, VerificationError, VerificationResult};

/// Wrapper trait for std::io::Read.
pub trait Serialize {
    fn serialize_into(&self, dst: &mut Vec<u8>);

    /// Serialized into a freshly-allocated vector of bytes.
    fn serialize_new(&self) -> impl AsRef<[u8]> {
        let mut buf = alloc::vec::Vec::new();
        self.serialize_into(&mut buf);
        buf.into_boxed_slice()
    }
}

/// Wrapper trait for serialization of prover messages into the proof string.
pub trait Deserialize: Sized {
    fn deserialize_from(buf: &mut &[u8]) -> VerificationResult<Self>;
}

impl<T: Encoding<[u8]>> Serialize for T {
    fn serialize_into(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(self.encode().as_ref());
    }
}

impl<const N: usize> Deserialize for [u8; N] {
    fn deserialize_from(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < N {
            return Err(VerificationError);
        }

        let (head, tail) = buf.split_at(N);
        *buf = tail;
        Ok(head.try_into().unwrap())
    }
}


impl<const N: usize, T: Deserialize> Deserialize for [T; N] {
    fn deserialize_from(buf: &mut &[u8]) -> VerificationResult<Self> {
        let vec: Vec<T> = (0..N)
            .map(|_| T::deserialize_from(buf))
            .collect::<Result<Vec<_>, _>>()?;

        // This is safe because we know vec.len() == N from the iterator above
        Ok(vec.try_into().unwrap_or_else(|_| unreachable!()))
    }
}
