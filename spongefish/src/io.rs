use alloc::vec::Vec;

use crate::{codecs::Encoding, VerificationError, VerificationResult};

/// Trait for serialization of an object as a NARG string.
///
/// # Semantics
///
/// When using a byte-oriented hash function, the serialized object
/// is the same as what's absorbed by the [DuplexSpongeInterface].
///
/// When serializing integers modulo N, serialization is expected to
/// follow the [I2OSP] conversion procedure from RFC8017, including for
/// prime-order finite fields.
/// Serialization of elements in a field extensions must serialize each base field element.
///
/// [I2OSP]: https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
/// [DuplexSpongeInterface]: [`crate::DuplexSpongeInterface`]
pub trait NargSerialize {
    /// Serializes `self` into `dst` by extending the vector.
    ///
    /// # Safety
    ///
    /// This procedure must compute an injective map.
    fn serialize_into_narg(&self, dst: &mut Vec<u8>);

    /// Shorthand for [`NargSerialize::serialize_into_narg`] for an empty byte array.
    fn serialize_into_new_narg(&self) -> impl AsRef<[u8]> {
        let mut buf = alloc::vec::Vec::new();
        self.serialize_into_narg(&mut buf);
        buf.into_boxed_slice()
    }
}

/// Trait for reading an object from a NARG string.
///
/// # Semantics
///
/// All objects serialized using [`NargSerialize`] must be de-serializable
/// (i.e., return `Ok(Self)`).
/// When de-serializing integers modulo N, this procedure is expected to compute the
/// conversion procedure [OS2IP] from RFC8017.
/// Prime-order fields must follow the same convention (seen as $Z/pZ$ elements),
/// and field extensions must serialize each of their base field elements.
///
/// [OS2IP]: https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
pub trait NargDeserialize: Sized {
    /// This map must compute the inverse of [`NargSerialize::serialize_into_narg`],
    /// or return an error if a pre-image does not exist.
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self>;
}

impl<T: Encoding<[u8]>> NargSerialize for T {
    /// Serialization for byte strings is the identity map.
    fn serialize_into_narg(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(self.encode().as_ref());
    }
}

impl<const N: usize> NargDeserialize for [u8; N] {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < N {
            return Err(VerificationError);
        }

        let (head, tail) = buf.split_at(N);
        *buf = tail;
        Ok(head.try_into().unwrap())
    }
}

impl<const N: usize, T: NargDeserialize> NargDeserialize for [T; N] {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        let vec: Vec<T> = (0..N)
            .map(|_| T::deserialize_from_narg(buf))
            .collect::<Result<Vec<_>, _>>()?;

        // This is safe because we know vec.len() == N from the iterator above
        Ok(vec.try_into().unwrap_or_else(|_| unreachable!()))
    }
}

impl NargDeserialize for u32 {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        NargDeserialize::deserialize_from_narg(buf).map(Self::from_le_bytes)
    }
}
