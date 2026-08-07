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
/// Serialization of elements in a field extension must serialize each base field element.
///
/// [I2OSP]: https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
/// [DuplexSpongeInterface]: crate::DuplexSpongeInterface
pub trait NargSerialize {
    /// Serializes `self` into `dst` by extending the vector.
    ///
    /// # Safety
    ///
    /// This procedure must output a prefix-free string.
    /// The bytes appended for one value must be exactly the bytes that the matching
    /// [`NargDeserialize`] implementation consumes on success.
    fn serialize_into_narg(&self, dst: &mut Vec<u8>);

    /// Shorthand for [`NargSerialize::serialize_into_narg`] into a freshly allocated buffer.
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
/// and field extensions must deserialize each of their base field elements.
/// Implementations must advance `buf` past the consumed bytes on success.
/// That is, after a successful call, `*buf` must point to the first byte after the
/// deserialized value.
///
/// [OS2IP]: https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
pub trait NargDeserialize: Sized {
    /// This map must compute the inverse of [`NargSerialize::serialize_into_narg`],
    /// or return an error if a pre-image does not exist.
    ///
    /// On success, implementations must advance `buf` by exactly the bytes they consumed.
    /// On failure, implementations must leave `buf` unchanged.
    /// Composite parsers should stage cursor movement on a local copy and commit on success.
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self>;
}

impl<T: Encoding<[u8]>> NargSerialize for T {
    /// Serialization for byte strings is the identity map.
    fn serialize_into_narg(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(self.encode().as_ref());
    }
}

impl<const N: usize, T: NargDeserialize> NargDeserialize for [T; N] {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        let mut rest = *buf;
        let mut failed = false;

        // Parsed in place rather than through a `Vec<T>` + `try_into`: the
        // vector cost one heap allocation per array on the verifier's hot
        // path, and `[T; N]` needs no allocation at all. The intermediate is
        // `[VerificationResult<T>; N]` because `array::from_fn` must yield a
        // value for every slot and there is nothing to yield once parsing has
        // failed; `try_from_fn` would say this directly but is unstable.
        let parsed: [VerificationResult<T>; N] = core::array::from_fn(|_| {
            if failed {
                // Short-circuit, matching the `collect::<Result<_, _>>()` this
                // replaces: no element is parsed after the first failure.
                return Err(VerificationError);
            }
            let element = T::deserialize_from_narg(&mut rest);
            failed = element.is_err();
            element
        });

        if failed {
            // `rest` is discarded, so `*buf` is left where it was.
            return Err(VerificationError);
        }
        *buf = rest;
        Ok(parsed.map(|element| element.unwrap_or_else(|_| unreachable!("checked above"))))
    }
}

macro_rules! impl_int_deserialize {
    ($($type:ty),*) => {$(
        /// Little-endian, matching the [`Encoding`] convention for integers.
        impl NargDeserialize for $type {
            fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
                const LEN: usize = core::mem::size_of::<$type>();
                if buf.len() < LEN {
                    return Err(VerificationError);
                }
                let (head, tail) = buf.split_at(LEN);
                *buf = tail;
                Ok(Self::from_le_bytes(head.try_into().unwrap()))
            }
        }
    )*};
}

impl_int_deserialize!(u8, u16, u32, u64, u128);
