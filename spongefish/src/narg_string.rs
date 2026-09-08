use crate::VerificationError;

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

    /// Whether the whole NARG string has been consumed.
    ///
    /// This is the only thing a parser may ask about what is left. How many
    /// bytes remain is deliberately not exposed: a deserializer that sizes a
    /// read from it is framing the message by the length of the surrounding
    /// NARG string rather than by its own encoding, which is a soundness
    /// hazard as soon as that message stops being the last one. A prefix-free
    /// encoding can always be read forward, as from a socket.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.position == self.narg_string.len()
    }

    /// The bytes not yet consumed. Internal: see [`NargReader::is_empty`].
    const fn unread(&self) -> &'a [u8] {
        // `position <= narg_string.len()` is maintained by `take`, the only
        // method that advances it, so this split never panics.
        self.narg_string.split_at(self.position).1
    }

    /// Consumes the next `len` bytes.
    ///
    /// Returns [`VerificationError`] if fewer than `len` bytes remain, leaving
    /// the cursor where it was — a truncated NARG string can never make a
    /// parser read past its end. `len` may come from the NARG string itself:
    /// an over-long length prefix fails here rather than being trusted.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8], VerificationError> {
        let (head, _) = self
            .unread()
            .split_at_checked(len)
            .ok_or(VerificationError)?;
        self.position += len;
        Ok(head)
    }

    /// Consumes the next `N` bytes as a fixed-size array.
    ///
    /// The fixed-length read that carries most prover messages: a compressed
    /// group element, a canonical scalar, a digest.
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N], VerificationError> {
        let (head, _) = self
            .unread()
            .split_first_chunk::<N>()
            .ok_or(VerificationError)?;
        self.position += N;
        Ok(*head)
    }
}

/// Trait for reading an object from a NARG string.
///
/// # Semantics
///
/// All objects encoded using [`Encoding`] must be de-serializable
/// (i.e., return `Ok(Self)`).
/// When de-serializing integers modulo N, this procedure is expected to compute the
/// conversion procedure [OS2IP] from RFC8017.
/// Prime-order fields must follow the same convention (seen as $Z/pZ$ elements),
/// and field extensions must deserialize each of their base field elements.
///
/// [OS2IP]: https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
pub trait NargDeserialize: Sized {
    /// This map must compute the inverse of [`Encoding::encode`],
    /// or return an error if a pre-image does not exist.
    ///
    /// Implementations read through [`NargReader`].
    /// A failed parse leaves the reader wherever it stopped.
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError>;

    /// Reads `N` consecutive values: the body of `[Self; N]`'s implementation.
    ///
    /// The batch deserialization method, so that a whole array of prover message can be read at once.
    ///
    /// # Security
    ///
    /// An override **MUST** accept exactly the inputs that `N` calls to
    /// [`NargDeserialize::deserialize_from_narg`] accept. It **MUST** consume
    /// exactly the same bytes they consume.
    fn deserialize_array_from_narg<const N: usize>(
        reader: &mut NargReader<'_>,
    ) -> Result<[Self; N], VerificationError> {
        let mut failed = false;

        // Parsed in place rather than through a `Vec<T>` + `try_into`: the
        // vector cost one heap allocation per array on the verifier's hot
        // path, and `[T; N]` needs no allocation at all. The intermediate is
        // `[Result<T, VerificationError>; N]` because `array::from_fn` must yield a
        // value for every slot and there is nothing to yield once parsing has
        // failed; `try_from_fn` would say this directly but is unstable.
        let parsed: [Result<Self, VerificationError>; N] = core::array::from_fn(|_| {
            if failed {
                // Short-circuit, matching the `collect::<Result<_, _>>()` this
                // replaces: no element is parsed after the first failure.
                return Err(VerificationError);
            }
            let element = Self::deserialize_from_narg(reader);
            failed = element.is_err();
            element
        });

        if failed {
            return Err(VerificationError);
        }
        Ok(parsed.map(|element| element.unwrap_or_else(|_| unreachable!("checked above"))))
    }
}

impl<const N: usize, T: NargDeserialize> NargDeserialize for [T; N] {
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
        T::deserialize_array_from_narg::<N>(reader)
    }
}

macro_rules! impl_int_deserialize {
    ($($type:ty),*) => {$(
        /// Little-endian, matching the [`Encoding`] convention for integers.
        impl NargDeserialize for $type {
            fn deserialize_from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
                const LEN: usize = core::mem::size_of::<$type>();
                Ok(Self::from_le_bytes(reader.take_array::<LEN>()?))
            }
        }
    )*};
}

impl_int_deserialize!(u16, u32, u64, u128);

/// A byte deserializes to itself, so `[u8; N]` is one fixed-size read rather
/// than `N` single-byte parses.
impl NargDeserialize for u8 {
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
        Ok(reader.take_array::<1>()?[0])
    }

    /// Exactly the `N` single-byte reads it replaces: the same bytes consumed,
    /// the same rejection of a short NARG string, one bounds check.
    fn deserialize_array_from_narg<const N: usize>(
        reader: &mut NargReader<'_>,
    ) -> Result<[Self; N], VerificationError> {
        reader.take_array::<N>()
    }
}
