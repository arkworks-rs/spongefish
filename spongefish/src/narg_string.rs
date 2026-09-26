use alloc::vec::Vec;
use core::cell::Cell;

use crate::VerificationError;

/// A forward-only cursor over a NARG string.
///
/// # Failure
///
/// Failed byte reads and errors returned through [`NargReader::read`] or
/// [`NargReader::read_with`] will poison the reader.
///
/// Once the reader is poisoned, every subsequent read will return [`VerificationError`],
/// including zero-length reads. Parsers will not be invoked on a poisoned reader.
///
/// This reader is not [`Sync`]: verification checks can poison it through
/// shared references. Reading bytes still requires exclusive access.
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
    /// read or verification check has failed.
    unread: Cell<Option<&'a [u8]>>,
}

impl<'a> NargReader<'a> {
    /// Creates a reader positioned at the start of `narg_string`.
    pub const fn new(narg_string: &'a [u8]) -> Self {
        Self {
            unread: Cell::new(Some(narg_string)),
        }
    }

    /// Whether the whole NARG string has been consumed.
    ///
    /// A reader in an invalid state will return `false`.
    pub const fn is_empty(&self) -> bool {
        match self.unread.get() {
            Some(unread) => unread.is_empty(),
            None => false,
        }
    }

    /// Return `true` if the reader is in an invalid state, `false` otherwise.
    pub const fn is_poisoned(&self) -> bool {
        self.unread.get().is_none()
    }

    /// Marks the reader invalid, including after the last byte was consumed.
    fn poison(&self) {
        self.unread.set(None);
    }

    /// Runs a verification check, retaining failures even if they are caught.
    pub(crate) fn check(&self, holds: impl FnOnce() -> bool) -> Result<(), VerificationError> {
        if self.is_poisoned() {
            return Err(VerificationError);
        }
        // A nested check can poison the reader through another shared reference.
        if holds() && !self.is_poisoned() {
            Ok(())
        } else {
            self.poison();
            Err(VerificationError)
        }
    }

    /// The bytes not yet consumed; `None` once the reader is poisoned.
    pub(crate) const fn unread(&self) -> Option<&'a [u8]> {
        self.unread.get()
    }

    /// Reads one value from the front of the NARG string.
    ///
    /// Returns [`VerificationError`] and poisons the reader on any parsing
    /// failure. A poisoned reader rejects the read without invoking the parser.
    pub fn read<T: FromNarg>(&mut self) -> Result<T, VerificationError> {
        self.read_with(T::from_narg)
    }

    /// Runs a parser, returning [`VerificationError`] on any parsing failure.
    ///
    /// A returned error will poison the reader.
    /// Use this for closure-based codecs and [`Self::read`] for types implementing
    /// [`FromNarg`].
    ///
    /// ```
    /// use spongefish::{NargReader, VerificationError};
    ///
    /// let mut reader = NargReader::new(&[255]);
    /// let result = reader.read_with(|reader| {
    ///     let [value] = reader.take_array::<1>()?;
    ///     if value > 1 {
    ///         return Err(VerificationError);
    ///     }
    ///     Ok(value != 0)
    /// });
    /// assert!(result.is_err());
    /// assert!(reader.is_poisoned());
    /// assert!(!reader.is_empty());
    /// ```
    pub fn read_with<T>(
        &mut self,
        parse: impl FnOnce(&mut Self) -> Result<T, VerificationError>,
    ) -> Result<T, VerificationError> {
        if self.is_poisoned() {
            return Err(VerificationError);
        }
        match parse(self) {
            Ok(value) if !self.is_poisoned() => Ok(value),
            _ => {
                self.poison();
                Err(VerificationError)
            }
        }
    }

    /// Reads `count` values in sequence.
    ///
    /// `count` is untrusted: initial allocation is capped, and an element that
    /// consumes no input is rejected, so a large count cannot spin without
    /// consuming the NARG string.
    pub fn read_vec<T: FromNarg>(&mut self, count: usize) -> Result<Vec<T>, VerificationError> {
        if self.is_poisoned() {
            return Err(VerificationError);
        }
        let mut elements = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let before = self.unread.get().map(<[u8]>::len);
            let element = self.read::<T>()?;
            if self.unread.get().map(<[u8]>::len) == before {
                self.poison();
                return Err(VerificationError);
            }
            elements.push(element);
        }
        Ok(elements)
    }

    /// Consumes the next `len` bytes.
    ///
    /// Returns [`VerificationError`] and poisons the reader if fewer than `len` bytes remain,
    /// so a truncated NARG string can never make a parser read past its end.
    /// `len` may come from the NARG string itself: an over-long length prefix
    /// fails here rather than being trusted.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8], VerificationError> {
        self.advance(|unread| unread.split_at_checked(len))
    }

    /// Consumes the next `N` bytes as a fixed-size array.
    ///
    /// The fixed-length read that carries most prover messages: a compressed
    /// group element, a canonical scalar, a digest. A short NARG string fails
    /// as in [`NargReader::take`].
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N], VerificationError> {
        self.advance(|unread| unread.split_first_chunk::<N>())
            .copied()
    }

    /// Splits a head off the unread tail and advances past it.
    ///
    /// A poisoned reader returns an error; a failed split poisons the reader.
    fn advance<T>(
        &mut self,
        split: impl FnOnce(&'a [u8]) -> Option<(T, &'a [u8])>,
    ) -> Result<T, VerificationError> {
        let Some((head, tail)) = self.unread.get().and_then(split) else {
            self.poison();
            return Err(VerificationError);
        };
        *self.unread.get_mut() = Some(tail);
        Ok(head)
    }
}

/// Trait for reading an object from a NARG string.
///
/// # Security
///
/// The input of [`FromNarg::from_narg`] is attacker-controlled.
/// An implementation **MUST**:
///
/// - be the inverse of the corresponding [`Encoding<u8>`][crate::Encoding] implementation:
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
/// - Return an error on validation failure and propagate errors from nested
///   parsers. Invoke nested parsers through [`NargReader::read`] or
///   [`NargReader::read_with`] so their returned errors automatically poison
///   the reader, even if subsequently caught.
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
pub trait FromNarg: Sized {
    /// This map must compute the inverse of [`Encoding::encode`](crate::Encoding::encode),
    /// or return an error if a pre-image does not exist.
    ///
    /// This is an implementation hook. Call [`NargReader::read`] to parse a
    /// value with automatic poisoning on error.
    ///
    /// # Security
    ///
    /// Implementations return `Err` for invalid input; the reader handles
    /// poisoning when the error reaches [`NargReader::read`] or
    /// [`NargReader::read_with`]. Use those entry points for nested parsers
    /// and propagate their errors. Calling this hook directly bypasses the
    /// wrapper and does not guarantee poisoning on a returned error.
    fn from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError>;

    /// Reads `N` consecutive values: the body of `[Self; N]`'s implementation.
    ///
    /// The batch deserialization method, so that a whole array of prover message can be read at once.
    /// Call `reader.read::<[T; N]>()` to parse an array with automatic poisoning.
    ///
    /// # Security
    ///
    /// An override **MUST** accept exactly the inputs that `N` calls to
    /// [`FromNarg::from_narg`] accept. It **MUST** consume
    /// exactly the same bytes they consume. Return errors to the reader and
    /// use [`NargReader::read`] or [`NargReader::read_with`] for nested parsers.
    /// As with the single-value hook, calling an override directly bypasses
    /// automatic poisoning of its returned errors.
    fn from_narg_array<const N: usize>(
        reader: &mut NargReader<'_>,
    ) -> Result<[Self; N], VerificationError> {
        // `array::from_fn` must yield a value for every slot, and there is
        // nothing to yield once parsing has failed, so the error is set aside
        // and the slots hold `Option`s; `try_from_fn` would say this directly
        // but is unstable. No element is parsed after the first failure.
        let mut failure = None;
        let parsed: [Option<Self>; N] = core::array::from_fn(|_| {
            if failure.is_some() {
                return None;
            }
            match reader.read::<Self>() {
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

impl<const N: usize, T: FromNarg> FromNarg for [T; N] {
    fn from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
        T::from_narg_array::<N>(reader)
    }
}

macro_rules! impl_int_deserialize {
    ($($type:ty),*) => {$(
        /// Little-endian, matching the [`Encoding`](crate::Encoding) convention for integers.
        impl FromNarg for $type {
            fn from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
                const LEN: usize = core::mem::size_of::<$type>();
                reader.take_array::<LEN>().map(Self::from_le_bytes)
            }
        }
    )*};
}

impl_int_deserialize!(u16, u32, u64, u128);

/// A byte deserializes to itself, so `[u8; N]` is one fixed-size read rather
/// than `N` single-byte parses.
impl FromNarg for u8 {
    fn from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
        reader.take_array::<1>().map(|[byte]| byte)
    }

    /// Exactly the `N` single-byte reads it replaces: the same bytes consumed,
    /// the same rejection of a short NARG string, one bounds check.
    fn from_narg_array<const N: usize>(
        reader: &mut NargReader<'_>,
    ) -> Result<[Self; N], VerificationError> {
        reader.take_array::<N>()
    }
}

/// The inverse of the `str` [`Encoding`](crate::Encoding): a little-endian
/// `u32` byte length, then that many bytes of valid UTF-8.
impl FromNarg for alloc::string::String {
    fn from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
        let len = usize::try_from(reader.read::<u32>()?).map_err(|_| VerificationError)?;
        let bytes = reader.take(len)?;
        core::str::from_utf8(bytes)
            .map(Into::into)
            .map_err(|_| VerificationError)
    }
}

#[cfg(test)]
mod tests {
    use super::{FromNarg, NargReader, VerificationError};

    #[test]
    fn string_round_trips_and_rejects_malformed_input() {
        use alloc::string::String;

        use crate::Encoding;

        for text in ["", "abc", "ünïcödé"] {
            let owned = String::from(text);
            let bytes = Encoding::<u8>::encode(&owned);
            let mut reader = NargReader::new(bytes.as_ref());
            assert_eq!(reader.read::<String>().unwrap(), text);
            assert!(reader.is_empty());
        }

        let rejected: [&[u8]; 4] = [
            &[3, 0, 0],                // truncated length
            &[3, 0, 0, 0, b'a', b'b'], // truncated body
            &[1, 0, 0, 0, 0xff],       // invalid UTF-8
            &[2, 0, 0, 0, 0xc3, 0x28], // invalid continuation byte
        ];
        for bytes in rejected {
            let mut reader = NargReader::new(bytes);
            assert!(reader.read::<String>().is_err());
            assert!(reader.is_poisoned());
        }
    }

    #[test]
    fn failures_at_any_position_reject_all_later_reads() {
        struct MustNotRun;

        impl FromNarg for MustNotRun {
            fn from_narg(_: &mut NargReader<'_>) -> Result<Self, VerificationError> {
                panic!("a poisoned reader must not invoke the parser");
            }
        }

        let bytes = [1, 2, 3];
        for consumed in [0, 1, bytes.len()] {
            let mut reader = NargReader::new(&bytes);
            let rejected = reader.read_with(|reader| {
                reader.take(consumed)?;
                Err::<(), _>(VerificationError)
            });
            assert!(rejected.is_err());
            assert!(reader.is_poisoned());
            assert!(!reader.is_empty());
            assert!(reader.take(0).is_err());
            assert!(reader.take(1).is_err());
            assert!(reader.take_array::<0>().is_err());
            assert!(reader.take_array::<1>().is_err());
            assert!(reader.read::<MustNotRun>().is_err());
            assert!(reader.read::<[MustNotRun; 0]>().is_err());
            assert!(reader.read_vec::<MustNotRun>(0).is_err());
            assert!(reader.read_vec::<MustNotRun>(usize::MAX).is_err());
            assert!(reader
                .read_with::<()>(|_| panic!("parser must not run"))
                .is_err());
        }
    }

    #[test]
    fn empty_reads_succeed_on_a_valid_reader() {
        let mut reader = NargReader::new(&[]);
        assert_eq!(reader.take(0).unwrap(), []);
        assert_eq!(reader.take_array::<0>().unwrap(), []);
        assert_eq!(reader.read::<[u16; 0]>().unwrap(), []);
        assert_eq!(reader.read_vec::<u8>(0).unwrap(), []);
        assert!(reader.read_with(|_| Ok(())).is_ok());
        assert!(reader.is_empty());
        assert!(!reader.is_poisoned());
    }

    #[test]
    fn catching_an_inner_parser_error_cannot_return_success() {
        let mut reader = NargReader::new(&[1]);
        let result = reader.read_with(|reader| {
            let rejected = reader.read_with(|reader| {
                assert_eq!(reader.take_array::<1>()?, [1]);
                Err::<(), _>(VerificationError)
            });
            assert!(rejected.is_err());
            Ok(())
        });
        assert!(result.is_err());
        assert!(reader.is_poisoned());
        assert!(!reader.is_empty());
    }

    #[test]
    fn a_parser_cannot_swallow_a_failed_byte_read() {
        struct Lenient;

        impl FromNarg for Lenient {
            fn from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
                let _ = reader.take(2);
                Ok(Self)
            }
        }

        let mut reader = NargReader::new(&[1]);
        assert!(reader.read::<Lenient>().is_err());
        assert!(reader.is_poisoned());
        assert!(!reader.is_empty());
    }

    #[test]
    fn default_array_stops_on_an_element_error() {
        #[derive(Debug, PartialEq)]
        struct Byte(u8);

        impl FromNarg for Byte {
            fn from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
                // No element may be parsed after a failure.
                assert!(!reader.is_poisoned());
                let [byte] = reader.take_array()?;
                if byte == 255 {
                    return Err(VerificationError);
                }
                Ok(Self(byte))
            }
        }

        let mut reader = NargReader::new(&[1, 2, 3]);
        assert_eq!(reader.read::<[Byte; 2]>().unwrap(), [Byte(1), Byte(2)]);
        assert_eq!(reader.take(1).unwrap(), [3]);

        for bytes in [&[1, 255][..], &[1, 255, 3][..]] {
            let mut reader = NargReader::new(bytes);
            assert!(reader.read::<[Byte; 3]>().is_err());
            assert!(reader.is_poisoned());
            assert!(!reader.is_empty());
            assert!(reader.take(1).is_err());
        }
    }

    #[test]
    fn reader_observes_array_override_errors() {
        struct Rejected;

        impl FromNarg for Rejected {
            fn from_narg(_: &mut NargReader<'_>) -> Result<Self, VerificationError> {
                panic!("the array override must be used");
            }

            fn from_narg_array<const N: usize>(
                reader: &mut NargReader<'_>,
            ) -> Result<[Self; N], VerificationError> {
                reader.take(N)?;
                Err(VerificationError)
            }
        }

        for bytes in [&[1, 2][..], &[1, 2, 3][..]] {
            let mut reader = NargReader::new(bytes);
            assert!(reader.read::<[Rejected; 2]>().is_err());
            assert!(reader.is_poisoned());
            assert!(!reader.is_empty());
            assert!(reader.take(1).is_err());
        }
    }
}
