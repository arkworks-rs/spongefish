use alloc::vec::Vec;

use crate::VerificationError;

/// A forward-only cursor over a NARG string.
///
/// # Failure
///
/// A failed read poisons the reader: every later read fails, it is never
/// empty, and the NARG verifier rejects the message even if the failure was
/// caught. Drop the reader and report the error.
///
/// ```
/// use spongefish::NargReader;
///
/// let bytes = [1u8, 0, 0, 0, 2, 0, 0, 0];
/// let mut reader = NargReader::new(&bytes);
/// assert_eq!(reader.read::<u32>().unwrap(), 1);
/// assert_eq!(reader.read::<u32>().unwrap(), 2);
/// assert!(reader.is_empty());
/// ```
#[derive(Debug)]
pub struct NargReader<'a> {
    /// The bytes not yet consumed, shortened by every `take`; `None` once a
    /// read has failed.
    unread: Option<&'a [u8]>,
}

impl<'a> NargReader<'a> {
    /// Creates a reader positioned at the start of `narg_string`.
    #[must_use]
    pub const fn new(narg_string: &'a [u8]) -> Self {
        Self {
            unread: Some(narg_string),
        }
    }

    /// Whether the whole NARG string has been consumed.
    ///
    /// A reader in an invalid state will return `false`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        match self.unread {
            Some(unread) => unread.is_empty(),
            None => false,
        }
    }

    /// Return `true` if the reader is in an invalid state, `false` otherwise.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.unread.is_none()
    }

    /// The bytes not yet consumed; `None` once the reader is poisoned.
    pub(crate) const fn unread(&self) -> Option<&'a [u8]> {
        self.unread
    }

    /// Reads one value from the front of the NARG string.
    ///
    /// A failure poisons the reader.
    pub fn read<T: NargDeserialize>(&mut self) -> Result<T, T::Error> {
        self.read_with(T::deserialize_from_narg)
    }

    /// Runs `parse` on the reader; a failure poisons it.
    pub(crate) fn read_with<T, E>(
        &mut self,
        parse: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let result = parse(self);
        if result.is_err() {
            self.unread = None;
        }
        result
    }

    /// Reads `count` values in sequence.
    ///
    /// `count` is untrusted: allocation is capped, and an element that
    /// consumes no input is rejected, so a large count cannot spin without
    /// consuming the NARG string.
    pub fn read_vec<T: NargDeserialize>(
        &mut self,
        count: usize,
    ) -> Result<Vec<T>, VerificationError> {
        let mut elements = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let before = self.unread.map(<[u8]>::len);
            let element = self.read::<T>().map_err(Into::into)?;
            if self.unread.map(<[u8]>::len) == before {
                self.unread = None;
                return Err(VerificationError);
            }
            elements.push(element);
        }
        Ok(elements)
    }

    /// Consumes the next `len` bytes.
    ///
    /// Returns `None` and poisons the reader if fewer than `len` bytes remain,
    /// so a truncated NARG string can never make a parser read past its end.
    /// `len` may come from the NARG string itself: an over-long length prefix
    /// fails here rather than being trusted.
    pub fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        self.advance(|unread| unread.split_at_checked(len))
    }

    /// Consumes the next `N` bytes as a fixed-size array.
    ///
    /// The fixed-length read that carries most prover messages: a compressed
    /// group element, a canonical scalar, a digest. A short NARG string fails
    /// as in [`NargReader::take`].
    pub fn take_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.advance(|unread| unread.split_first_chunk::<N>())
            .copied()
    }

    /// Splits a head off the unread tail and advances past it.
    ///
    /// A poisoned reader yields nothing, and a `split` that yields nothing
    /// poisons the reader.
    fn advance<T>(&mut self, split: impl FnOnce(&'a [u8]) -> Option<(T, &'a [u8])>) -> Option<T> {
        let Some((head, tail)) = self.unread.and_then(split) else {
            self.unread = None;
            return None;
        };
        self.unread = Some(tail);
        Some(head)
    }
}

/// Trait for reading an object from a NARG string.
///
/// # Security
///
/// The input of [`NargDeserialize::deserialize_from_narg`] is attacker-controlled.
/// An implementation **MUST**:
///
/// - be the inverse of the corresponding [`Encoding<[u8]>`] implementation:
///   every value produced by `Encoding::encode` must deserialize to that value,
///   and there must be at most one valid value for each possible input.
///   Accepting multiple encodings for the same value can make a proof malleable.
///   Invalid inputs must be rejected.
/// - Lengths, counts, and other hints read from the NARG string are untrusted and must
///   be checked before they are used for indexing, allocation, or arithmetic;
/// - For a returned value `T`, all validation for that value must be satisfied. For
///   example, an elliptic-curve point must be on the intended curve and in
///   the intended subgroup, and a field element or scalar must be in its
///   canonical range. Any additional validity condition required by the
///   protocol must also be checked;
/// - It must not panic on invalid input, read beyond the input, or silently substitute a default value.
///   Implementations that allocate based on attacker-controlled input should impose an appropriate bound before
///   allocating.
///
/// The implementation need not consume the entire reader.
/// However, the caller must reject trailing bytes after the complete NARG has been parsed.
///
/// # Requirements
///
/// This procedure is expected to follow the Deserialization section of
/// [draft-irtf-cfrg-fiat-shamir].
///
/// [draft-irtf-cfrg-fiat-shamir]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
pub trait NargDeserialize: Sized {
    /// What a failed parse reports.
    ///
    /// The NARG verifier reports [`VerificationError`] and nothing more, so
    /// that is what this converts into; an implementation is free to carry more
    /// detail for its own callers. `Debug` makes a read result unwrappable.
    type Error: Into<VerificationError> + core::fmt::Debug;

    /// This map must compute the inverse of [`Encoding::encode`](crate::Encoding::encode),
    /// or return an error if a pre-image does not exist.
    ///
    /// Implementations read through [`NargReader`].
    ///
    /// # Security
    ///
    /// A failure poisons the reader: later reads fail, and the message is
    /// rejected even if the error is caught. Propagate it.
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> Result<Self, Self::Error>;

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
    ) -> Result<[Self; N], Self::Error> {
        // `array::from_fn` must yield a value for every slot, and there is
        // nothing to yield once parsing has failed, so the error is set aside
        // and the slots hold `Option`s; `try_from_fn` would say this directly
        // but is unstable. No element is parsed after the first failure.
        let mut failure = None;
        let parsed: [Option<Self>; N] = core::array::from_fn(|_| {
            if failure.is_some() {
                return None;
            }
            match Self::deserialize_from_narg(reader) {
                Ok(element) => Some(element),
                Err(error) => {
                    failure = Some(error);
                    None
                }
            }
        });

        if let Some(error) = failure {
            return Err(error);
        }
        Ok(parsed.map(|element| element.unwrap_or_else(|| unreachable!("checked above"))))
    }
}

impl<const N: usize, T: NargDeserialize> NargDeserialize for [T; N] {
    type Error = T::Error;

    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> Result<Self, Self::Error> {
        T::deserialize_array_from_narg::<N>(reader)
    }
}

macro_rules! impl_int_deserialize {
    ($($type:ty),*) => {$(
        /// Little-endian, matching the [`Encoding`](crate::Encoding) convention for integers.
        impl NargDeserialize for $type {
            type Error = VerificationError;

            fn deserialize_from_narg(reader: &mut NargReader<'_>) -> Result<Self, Self::Error> {
                const LEN: usize = core::mem::size_of::<$type>();
                reader
                    .take_array::<LEN>()
                    .map(Self::from_le_bytes)
                    .ok_or(VerificationError)
            }
        }
    )*};
}

impl_int_deserialize!(u16, u32, u64, u128);

/// A byte deserializes to itself, so `[u8; N]` is one fixed-size read rather
/// than `N` single-byte parses.
impl NargDeserialize for u8 {
    type Error = VerificationError;

    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> Result<Self, Self::Error> {
        reader
            .take_array::<1>()
            .map(|[byte]| byte)
            .ok_or(VerificationError)
    }

    /// Exactly the `N` single-byte reads it replaces: the same bytes consumed,
    /// the same rejection of a short NARG string, one bounds check.
    fn deserialize_array_from_narg<const N: usize>(
        reader: &mut NargReader<'_>,
    ) -> Result<[Self; N], Self::Error> {
        reader.take_array::<N>().ok_or(VerificationError)
    }
}
