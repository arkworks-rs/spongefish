use alloc::vec::Vec;

use crate::{codecs::Encoding, VerificationError, VerificationResult};

/// A forward-only cursor over a NARG string.
///
/// # Failure
///
/// A parser that fails leaves the reader wherever the failure occurred.
/// Composite parsers therefore need no staging of their own, and propagating with
/// `?` is correct.
///
/// ```
/// use spongefish::{NargDeserialize, NargReader};
///
/// let bytes = [1u8, 0, 0, 0, 2, 0, 0, 0];
/// let mut reader = NargReader::new(&bytes);
/// assert_eq!(u32::deserialize_from_narg(&mut reader).unwrap(), 1);
/// assert_eq!(reader.consumed(), 4);
/// assert_eq!(u32::deserialize_from_narg(&mut reader).unwrap(), 2);
/// assert!(reader.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct NargReader<'a> {
    /// The full NARG string this reader was created over.
    narg_string: &'a [u8],
    /// How far into `narg_string` the cursor has advanced; never decreases and
    /// never exceeds `narg_string.len()`.
    position: usize,
}

impl<'a> NargReader<'a> {
    /// Creates a reader positioned at the start of `narg_string`.
    #[must_use]
    pub const fn new(narg_string: &'a [u8]) -> Self {
        Self {
            narg_string,
            position: 0,
        }
    }

    /// The number of bytes consumed so far.
    ///
    /// These are exactly `narg_string[..consumed]`, the bytes a byte-oriented
    /// sponge absorbs for the messages read through this reader.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.position
    }

    /// The bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] {
        // `position <= narg_string.len()` is maintained by `take`, the only
        // method that advances it, so this split never panics.
        self.narg_string.split_at(self.position).1
    }

    /// The number of bytes not yet consumed.
    #[must_use]
    pub const fn remaining_len(&self) -> usize {
        self.narg_string.len() - self.position
    }

    /// Whether the whole NARG string has been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining_len() == 0
    }

    /// Consumes the next `len` bytes.
    ///
    /// Returns [`VerificationError`] if fewer than `len` bytes remain, leaving
    /// the cursor where it was — a truncated NARG string can never make a
    /// parser read past its end. `len` may come from the NARG string itself:
    /// an over-long length prefix fails here rather than being trusted.
    pub fn take(&mut self, len: usize) -> VerificationResult<&'a [u8]> {
        let (head, _) = self
            .remaining()
            .split_at_checked(len)
            .ok_or(VerificationError)?;
        self.position += len;
        Ok(head)
    }

    /// Consumes the next `N` bytes as a fixed-size array.
    ///
    /// The fixed-length read that carries most prover messages: a compressed
    /// group element, a canonical scalar, a digest.
    pub fn take_array<const N: usize>(&mut self) -> VerificationResult<[u8; N]> {
        let (head, _) = self
            .remaining()
            .split_first_chunk::<N>()
            .ok_or(VerificationError)?;
        self.position += N;
        Ok(*head)
    }
}

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
///
/// [OS2IP]: https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
pub trait NargDeserialize: Sized {
    /// This map must compute the inverse of [`NargSerialize::serialize_into_narg`],
    /// or return an error if a pre-image does not exist.
    ///
    /// Implementations read through [`NargReader`].
    /// A failed parse leaves the reader wherever it stopped.
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> VerificationResult<Self>;
}

impl<T: Encoding<[u8]>> NargSerialize for T {
    /// Serialization for byte strings is the identity map.
    fn serialize_into_narg(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(self.encode().as_ref());
    }
}

impl<const N: usize, T: NargDeserialize> NargDeserialize for [T; N] {
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> VerificationResult<Self> {
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
            let element = T::deserialize_from_narg(reader);
            failed = element.is_err();
            element
        });

        if failed {
            return Err(VerificationError);
        }
        Ok(parsed.map(|element| element.unwrap_or_else(|_| unreachable!("checked above"))))
    }
}

macro_rules! impl_int_deserialize {
    ($($type:ty),*) => {$(
        /// Little-endian, matching the [`Encoding`] convention for integers.
        impl NargDeserialize for $type {
            fn deserialize_from_narg(reader: &mut NargReader<'_>) -> VerificationResult<Self> {
                const LEN: usize = core::mem::size_of::<$type>();
                Ok(Self::from_le_bytes(reader.take_array::<LEN>()?))
            }
        }
    )*};
}

impl_int_deserialize!(u8, u16, u32, u64, u128);
