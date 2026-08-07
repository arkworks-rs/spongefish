//! Maps for encoding prover messages and decoding verifier messages.

use alloc::vec::Vec;

/// Marker trait for types that have encoding and decoding maps.
///
/// A type is a [`Codec`] if it implements [`Encoding`], [`Decoding`],
/// [`NargSerialize`][crate::NargSerialize], and [`NargDeserialize`][crate::NargDeserialize].
///
/// # Derive Macros
///
/// With the `derive` feature enabled:
///
/// ```
/// # #[cfg(feature = "derive")]
/// # {
/// use spongefish::Codec;
///
/// #[derive(Codec)]
/// struct MyStruct {
///     field1: u32,
///     field2: u32,
///     #[spongefish(skip)]  // Skip this field (uses Default)
///     cached: Option<String>,
/// }
/// # }
/// ```
///
/// Equivalent to deriving `Encoding`, `Decoding`, and `NargDeserialize`. Fields marked with
/// `#[spongefish(skip)]` are initialized via `Default`; any other
/// `#[spongefish(..)]` form is a compile error.
///
/// A skipped field is not bound by the Fiat-Shamir transformation — it reaches
/// neither the sponge nor the NARG string. Skipping every field therefore
/// leaves a zero-length encoding, under which all values of the struct are
/// indistinguishable; that is injective, and so admissible, only for a type
/// with a single inhabitant.
pub trait Codec<T = [u8]>:
    crate::NargDeserialize + crate::NargSerialize + Encoding<T> + Decoding<T>
where
    T: ?Sized,
{
}

/// Interface for turning a type into a duplex sponge input.
///
/// [`Encoding<T>`] defines an encoding into a type `T`.
/// By default `T = [u8]` in order to serve encoding for byte-oriented hash functions.
///
/// # Safety
///
/// [`spongefish`][`crate`] assumes that prover and verifier will know the length of all the prover messages.
/// [`Encoding`] must be **prefix-free**: the output of [`Encoding::encode`] is never a prefix of the
/// encoding of any other instance of the same type.
///
/// More information on the theoretical requirements is in [[CO25], Theorem 6.2].
///
/// # Encoding conventions
///
/// For byte sequences, encoding must be the identity function.
/// Strings are encoded as their little-endian `u32` byte length followed by their UTF-8 bytes.
/// Integers are encoded as their fixed-width little-endian bytes.
///
/// [CO25]: https://eprint.iacr.org/2025/536.pdf
pub trait Encoding<T = [u8]>
where
    T: ?Sized,
{
    /// The function encoding prover messages into inputs to be absorbed by the duplex sponge.
    ///
    /// This map must be injective. The computation of the pre-image of this map will affect the extraction time.
    fn encode(&self) -> impl AsRef<T>;
}

/// The interface for all types that can be turned into verifier messages.
pub trait Decoding<T = [u8]>
where
    T: ?Sized,
{
    /// The output type (and length) expected by the duplex sponge.
    ///
    /// # Example
    ///
    /// ```
    /// # use spongefish::{Decoding, ByteArray};
    /// let repr: ByteArray<4> = Default::default();
    /// assert_eq!(repr.as_ref(), &[0u8; 4]);
    /// ```
    type Repr: Default + AsMut<T>;

    /// The distribution-preserving map, that re-maps a squeezed output [`Decoding::Repr`] into a verifier message.
    ///
    /// This map is not exactly a decoding function (e.g., it need not be injective). What is demanded from this function is that
    /// it preserves the uniform distribution: if [`Decoding::Repr`] is distributed uniformly at random, then so is the output of [`decode`][Decoding::decode].
    fn decode(buf: Self::Repr) -> Self;
}

impl<U, T> Encoding<U> for &T
where
    U: ?Sized,
    T: Encoding<U> + ?Sized,
{
    fn encode(&self) -> impl AsRef<U> {
        (*self).encode()
    }
}

/// The array codec's output.
///
/// When every element encodes to exactly one unit — the `[u8; N]` case that
/// carries most prover messages — the whole encoding is exactly `N` units and
/// lives inline. Otherwise it goes to the heap, as before.
///
/// The inline variant is `[U; N]`: its size is exactly the size of the array
/// being encoded, so this can never blow up the stack for a wide alphabet the
/// way a fixed unit budget could.
enum ArrayEncoding<U, const N: usize> {
    Inline([U; N]),
    Heap(Vec<U>),
}

impl<U, const N: usize> AsRef<[U]> for ArrayEncoding<U, N> {
    fn as_ref(&self) -> &[U] {
        match self {
            Self::Inline(units) => units,
            Self::Heap(units) => units,
        }
    }
}

impl<U: Clone, T: Encoding<[U]>, const N: usize> Encoding<[U]> for [T; N] {
    fn encode(&self) -> impl AsRef<[U]> {
        if let Some(first) = self.first() {
            let head = first.encode();
            let head = head.as_ref();

            // Fast path: one unit per element, so the total is `N` units and
            // the buffer is exactly sized. `uniform` records whether that held
            // for *every* element, not just the first: an element codec whose
            // width varies falls back to the heap path below, re-encoding from
            // scratch. The filler written for such an element is never
            // observed, because `uniform` then discards the whole buffer.
            //
            // A uniform array costs exactly one encode per element. Once a
            // width mismatch is found the remaining slots are filled without
            // encoding at all, since the buffer they would fill is about to be
            // thrown away — so the worst case is one encode per element here
            // plus one in the fallback, never three.
            if head.len() == 1 {
                let head_unit = head[0].clone();
                let mut uniform = true;
                let units: [U; N] = core::array::from_fn(|index| {
                    // Element 0 reuses the peek above.
                    if index == 0 || !uniform {
                        return head_unit.clone();
                    }
                    let encoded = self[index].encode();
                    let encoded = encoded.as_ref();
                    if encoded.len() == 1 {
                        encoded[0].clone()
                    } else {
                        uniform = false;
                        head_unit.clone()
                    }
                });
                if uniform {
                    return ArrayEncoding::Inline(units);
                }
            }

            let mut output = Vec::new();
            // Elements of an array share a type, and every codec in this crate
            // is fixed-width, so the first element's length times `N` is the
            // exact total: one allocation instead of `log2(N)` reallocations.
            // A variable-width element codec merely makes this a hint — the
            // vector still grows on its own, and the bytes are unchanged.
            output.reserve_exact(head.len().saturating_mul(N));
            // `head` again rather than re-encoding element 0. Reaching here
            // after the fast path bailed out already means one wasted encode
            // per element; the fallback exists for variable-width codecs, so
            // it should not also be the most expensive path per element.
            output.extend_from_slice(head);
            for element in &self[1..] {
                output.extend_from_slice(element.encode().as_ref());
            }
            ArrayEncoding::Heap(output)
        } else {
            ArrayEncoding::Heap(Vec::new())
        }
    }
}

macro_rules! impl_int_encoding {
    ($type: ty) => {
        impl Encoding<[u8]> for $type {
            fn encode(&self) -> impl AsRef<[u8]> {
                self.to_le_bytes()
            }
        }
    };
}

macro_rules! impl_int_decoding {
    ($type: ty) => {
        impl Decoding<[u8]> for $type {
            type Repr = ByteArray<{ core::mem::size_of::<$type>() }>;

            fn decode(buf: Self::Repr) -> Self {
                <$type>::from_le_bytes(Decoding::decode(buf))
            }
        }
    };
}

impl_int_encoding!(u8);
impl_int_decoding!(u8);
impl_int_encoding!(u16);
impl_int_decoding!(u16);
impl_int_encoding!(u32);
impl_int_decoding!(u32);
impl_int_encoding!(u64);
impl_int_decoding!(u64);
impl_int_encoding!(u128);
impl_int_decoding!(u128);

#[derive(Debug, Clone)]
pub struct ByteArray<const N: usize>([u8; N]);

impl<const N: usize> Default for ByteArray<N> {
    fn default() -> Self {
        Self([0; N])
    }
}
impl<const N: usize> AsRef<[u8; N]> for ByteArray<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for ByteArray<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<const N: usize> Decoding<[u8]> for [u8; N] {
    type Repr = ByteArray<N>;

    fn decode(buf: Self::Repr) -> Self {
        buf.0
    }
}

/// Handy for serializing byte strings.
///
/// # Safety
///
/// This implementation is the identity map on `[u8]`.
/// > **Warning:**
/// > It is the responsibility of the caller to ensure that the byte string length is fixed by
/// > the surrounding protocol and that any value encoded this way is prefix-free. Otherwise,
/// > distinct prover messages may become ambiguous in the transcript.
impl Encoding<[u8]> for [u8] {
    fn encode(&self) -> impl AsRef<[u8]> {
        self
    }
}

/// Handy for serializing UTF-8 strings.
///
/// Strings are encoded as their little-endian `u32` byte length followed by their UTF-8 bytes.
/// This makes the byte-oriented encoding prefix-free.
impl Encoding<[u8]> for str {
    fn encode(&self) -> impl AsRef<[u8]> {
        let len: u32 = self
            .len()
            .try_into()
            .expect("string encoding requires length to fit in u32");
        let mut out = Vec::with_capacity(size_of::<u32>() + self.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(self.as_bytes());
        out
    }
}

impl<A, B> Encoding<[u8]> for (A, B)
where
    A: Encoding<[u8]>,
    B: Encoding<[u8]>,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        let (first, second) = (self.0.encode(), self.1.encode());
        let (first, second) = (first.as_ref(), second.as_ref());
        let mut output = Vec::with_capacity(first.len() + second.len());
        output.extend_from_slice(first);
        output.extend_from_slice(second);
        output
    }
}

impl<A, B, C> Encoding<[u8]> for (A, B, C)
where
    A: Encoding<[u8]>,
    B: Encoding<[u8]>,
    C: Encoding<[u8]>,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        let (first, second, third) = (self.0.encode(), self.1.encode(), self.2.encode());
        let (first, second, third) = (first.as_ref(), second.as_ref(), third.as_ref());
        let mut output = Vec::with_capacity(first.len() + second.len() + third.len());
        output.extend_from_slice(first);
        output.extend_from_slice(second);
        output.extend_from_slice(third);
        output
    }
}

/// A variable-length sequence, encoded with a `u32` element-count prefix.
///
/// [`Encoding`] for bare sequences must be prefix-free, which rules out
/// concatenating a variable number of element encodings: `[a]` would encode to
/// a strict prefix of `[a, b]`. This combinator restores prefix-freeness by
/// prepending the element count as a little-endian `u32` (the same convention
/// as the [`str`] codec), followed by each element's encoding in order.
///
/// The prover encodes a borrowed slice; the verifier reads back an owned
/// vector:
///
/// ```
/// # #[cfg(all(feature = "turboshake128", feature = "getrandom"))]
/// # {
/// use spongefish::{LengthPrefixed, ProverState, StdHash, VerifierState};
///
/// let session_id = spongefish::derive_session_id::<StdHash>(b"examples/LengthPrefixed");
/// let values = vec![7u32, 8, 9];
///
/// let mut prover_state = ProverState::<StdHash>::new(&session_id, &0u32);
/// prover_state.prover_message(&LengthPrefixed(&values[..]));
///
/// let mut verifier_state =
///     VerifierState::<StdHash>::new(&session_id, &0u32, prover_state.narg_string());
/// let LengthPrefixed(read_back): LengthPrefixed<Vec<u32>> =
///     verifier_state.prover_message().unwrap();
/// assert_eq!(read_back, values);
/// assert!(verifier_state.check_eof().is_ok());
/// # }
/// ```
///
/// The owned form also composes with `#[derive(Codec)]`, so a round message
/// may hold a `LengthPrefixed<Vec<T>>` field.
///
/// # Safety
///
/// The count prefix makes the encoding prefix-free even when the sequence
/// length is not fixed by the protocol, but the length still becomes part of
/// the transcript: prover and verifier absorb whatever count is sent.
/// Deserialization treats the count as untrusted: a prefix exceeding the
/// remaining NARG bytes is rejected up front, and the parse loop additionally
/// rejects any element that consumes zero bytes. Together these bound the work
/// by the number of remaining bytes for *every* element type, including
/// zero-width ones (a zero-width element makes the encoding non-injective, so
/// rejecting it is correct rather than merely defensive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthPrefixed<T>(pub T);

impl<T> LengthPrefixed<T> {
    /// Consumes the wrapper, returning the inner sequence.
    pub fn into_inner(self) -> T {
        self.0
    }
}

fn encode_length_prefixed<T: Encoding<[u8]>>(elements: &[T]) -> Vec<u8> {
    let len: u32 = elements
        .len()
        .try_into()
        .expect("length-prefixed encoding requires the element count to fit in u32");
    let mut iter = elements.iter();
    let Some(first) = iter.next() else {
        return len.to_le_bytes().to_vec();
    };
    let head = first.encode();
    let head = head.as_ref();
    // Every codec in this crate is fixed-width, so the first element's length
    // gives the exact total; a variable-width codec only makes it a hint.
    let total = head
        .len()
        .saturating_mul(elements.len())
        .saturating_add(size_of::<u32>());

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(head);
    for element in iter {
        out.extend_from_slice(element.encode().as_ref());
    }
    out
}

impl<T: Encoding<[u8]>> Encoding<[u8]> for LengthPrefixed<&[T]> {
    fn encode(&self) -> impl AsRef<[u8]> {
        encode_length_prefixed(self.0)
    }
}

impl<T: Encoding<[u8]>> Encoding<[u8]> for LengthPrefixed<alloc::vec::Vec<T>> {
    fn encode(&self) -> impl AsRef<[u8]> {
        encode_length_prefixed(&self.0)
    }
}

impl<T: crate::NargDeserialize> crate::NargDeserialize for LengthPrefixed<alloc::vec::Vec<T>> {
    fn deserialize_from_narg(buf: &mut &[u8]) -> crate::VerificationResult<Self> {
        let mut rest = *buf;
        let len = u32::deserialize_from_narg(&mut rest)? as usize;
        // Untrusted length: any element that parses consumes at least one byte
        // (enforced below), so a count exceeding the remaining bytes cannot
        // parse — reject it before looping.
        if len > rest.len() {
            return Err(crate::VerificationError);
        }
        // NOTE: `len` is attacker-controlled. Reserving `len` elements up
        // front would let a 4-byte count trigger a `len * size_of::<T>()`
        // allocation — an amplification the growing vector does not have. Cap
        // the hint so it still avoids the first reallocations for the typical
        // short sequence without handing an attacker a memory multiplier.
        let mut elements = Vec::with_capacity(usize::min(len, 64));
        for _ in 0..len {
            let remaining = rest.len();
            let element = T::deserialize_from_narg(&mut rest)?;
            // A zero-width element would make the encoding non-injective and
            // would let a huge count spin without consuming input; reject it.
            if rest.len() == remaining {
                return Err(crate::VerificationError);
            }
            elements.push(element);
        }
        *buf = rest;
        Ok(Self(elements))
    }
}

/// Blanket implementation of [`Codec`] for all types implementing
/// [`NargSerialize`][`crate::NargSerialize`],
/// [`NargDeserialize`][`crate::NargDeserialize`],
/// [`Encoding`], and [`Decoding`].
impl<T, E> Codec<T> for E
where
    T: ?Sized,
    E: crate::NargDeserialize + crate::NargSerialize + Encoding<T> + Decoding<T>,
{
}

#[cfg(test)]
mod tests {
    use super::{Encoding, LengthPrefixed};
    use crate::NargDeserialize;

    /// The `str` codec spans the inline/heap boundary as the string grows; the
    /// bytes must stay `u32` length prefix followed by UTF-8, throughout.
    #[test]
    fn str_encoding_is_stable_across_the_spill_boundary() {
        for len in [0usize, 1, 100, 123, 124, 125, 200, 1000] {
            let text = "x".repeat(len);
            let text = text.as_str();
            let encoded = Encoding::<[u8]>::encode(&text);
            let mut expected = alloc::vec::Vec::new();
            expected.extend_from_slice(&(len as u32).to_le_bytes());
            expected.extend_from_slice(text.as_bytes());
            assert_eq!(encoded.as_ref(), &expected[..], "len {len}");
        }
    }

    /// The length-prefixed codec now sizes its buffer from the first element's
    /// width. The bytes must not depend on that hint being right.
    #[test]
    fn length_prefixed_encoding_is_stable_across_the_spill_boundary() {
        for len in [0usize, 1, 30, 31, 32, 33, 100] {
            let values: alloc::vec::Vec<u32> = (0..len as u32).collect();
            let wrapper = LengthPrefixed(&values[..]);
            let encoded = wrapper.encode();
            let mut expected = alloc::vec::Vec::new();
            expected.extend_from_slice(&(len as u32).to_le_bytes());
            for value in &values {
                expected.extend_from_slice(&value.to_le_bytes());
            }
            assert_eq!(encoded.as_ref(), &expected[..], "len {len}");
        }
    }

    /// Cross-architecture guard: the `str` length prefix must be a fixed-width,
    /// little-endian `u32` on every target. If this ever regresses to a
    /// pointer-width `usize`, the prefix would be 4 bytes on wasm32 and 8 bytes on
    /// x86-64, so a 64-bit prover and a 32-bit verifier would derive different
    /// transcripts. A 32-bit CI lane (see the `wasm` job) runs this for real.
    #[test]
    fn str_length_prefix_is_fixed_width_u32_le() {
        let encoded = Encoding::<[u8]>::encode(&"abc");
        // 4-byte LE length (== 3) followed by the UTF-8 bytes — never 8 bytes.
        assert_eq!(encoded.as_ref(), &[3, 0, 0, 0, b'a', b'b', b'c']);

        // Empty string is just the four length bytes.
        let empty = Encoding::<[u8]>::encode(&"");
        assert_eq!(empty.as_ref(), &[0, 0, 0, 0]);
    }

    /// The count prefix is a fixed-width little-endian `u32` element count,
    /// followed by each element's encoding; the borrowed and owned forms
    /// encode identically.
    #[test]
    fn length_prefixed_encoding_layout() {
        let values = alloc::vec![0x0102_0304u32, 0x0506_0708];
        let borrowed_form = LengthPrefixed(&values[..]);
        let owned_form = LengthPrefixed(values.clone());
        let borrowed = borrowed_form.encode();
        let owned = owned_form.encode();
        assert_eq!(borrowed.as_ref(), owned.as_ref());
        assert_eq!(
            borrowed.as_ref(),
            &[2, 0, 0, 0, 4, 3, 2, 1, 8, 7, 6, 5],
            "u32 LE count, then each element's LE encoding"
        );

        // The empty sequence is just the four count bytes — not empty, so the
        // encoding stays prefix-free across lengths.
        let empty_form = LengthPrefixed::<&[u32]>(&[]);
        let empty = empty_form.encode();
        assert_eq!(empty.as_ref(), &[0, 0, 0, 0]);
    }

    /// Deserialization round-trips, rejects truncated element data, and
    /// rejects a count prefix exceeding the remaining bytes without looping.
    #[test]
    fn length_prefixed_deserialization_guards() {
        let values = alloc::vec![7u32, 8, 9];
        let wrapper = LengthPrefixed(&values[..]);
        let bytes = wrapper.encode();

        let mut cursor = bytes.as_ref();
        let LengthPrefixed(read_back) =
            LengthPrefixed::<alloc::vec::Vec<u32>>::deserialize_from_narg(&mut cursor).unwrap();
        assert_eq!(read_back, values);
        assert!(cursor.is_empty());

        // Truncated element data: the cursor must be left unchanged.
        let truncated = &bytes.as_ref()[..bytes.as_ref().len() - 1];
        let mut cursor = truncated;
        assert!(
            LengthPrefixed::<alloc::vec::Vec<u32>>::deserialize_from_narg(&mut cursor).is_err()
        );
        assert_eq!(cursor, truncated);

        // A huge count with no data behind it is rejected by the length
        // guard, before any element parsing.
        let bogus = [0xFF, 0xFF, 0xFF, 0xFF];
        let mut cursor = &bogus[..];
        assert!(
            LengthPrefixed::<alloc::vec::Vec<u32>>::deserialize_from_narg(&mut cursor).is_err()
        );
        assert_eq!(cursor, &bogus[..]);
    }

    /// An element codec whose encoded width depends on the *value*, not just
    /// the type. Contrived here, but not hypothetical: compressed SEC1 points
    /// encode the identity in one byte and every other point in 33.
    struct VariableWidth(usize);

    impl Encoding<[u8]> for VariableWidth {
        fn encode(&self) -> impl AsRef<[u8]> {
            alloc::vec![self.0 as u8; self.0]
        }
    }

    /// The array codec takes an inline fast path when the *first* element
    /// encodes to a single unit, then verifies that every other element did
    /// too. A variable-width codec must fall back to the heap path and still
    /// produce the plain concatenation — in particular for the dangerous
    /// ordering where a one-unit element comes first and a wider one follows.
    #[test]
    fn array_encoding_handles_variable_width_elements() {
        let cases: [[VariableWidth; 4]; 5] = [
            // One unit first, then wider: the ordering that would let a buggy
            // fast path commit a truncated encoding.
            [
                VariableWidth(1),
                VariableWidth(3),
                VariableWidth(1),
                VariableWidth(2),
            ],
            // Wider first: the fast path is never entered.
            [
                VariableWidth(3),
                VariableWidth(1),
                VariableWidth(1),
                VariableWidth(1),
            ],
            // Uniformly one unit: the fast path is entered and kept.
            [
                VariableWidth(1),
                VariableWidth(1),
                VariableWidth(1),
                VariableWidth(1),
            ],
            // Uniformly wider.
            [
                VariableWidth(4),
                VariableWidth(4),
                VariableWidth(4),
                VariableWidth(4),
            ],
            // A zero-width element among one-unit elements.
            [
                VariableWidth(1),
                VariableWidth(0),
                VariableWidth(1),
                VariableWidth(1),
            ],
        ];

        for case in &cases {
            let mut expected = alloc::vec::Vec::new();
            for element in case {
                expected.extend_from_slice(element.encode().as_ref());
            }
            let encoded = Encoding::<[u8]>::encode(case);
            assert_eq!(
                encoded.as_ref(),
                &expected[..],
                "widths {:?}",
                case.iter().map(|e| e.0).collect::<alloc::vec::Vec<_>>()
            );
        }

        // The empty array encodes to nothing, on either path.
        let empty: [VariableWidth; 0] = [];
        assert_eq!(Encoding::<[u8]>::encode(&empty).as_ref(), b"");
    }

    /// An element type whose deserializer consumes no input at all — the
    /// shape a derived unit struct takes.
    #[derive(Debug)]
    struct ZeroWidth;

    impl NargDeserialize for ZeroWidth {
        fn deserialize_from_narg(_buf: &mut &[u8]) -> crate::VerificationResult<Self> {
            Ok(Self)
        }
    }

    /// A zero-width element type must not let an attacker-chosen count spin the
    /// parse loop: the first element that consumes nothing is rejected, so the
    /// work stays bounded by the remaining bytes.
    #[test]
    fn length_prefixed_rejects_zero_width_elements() {
        // Count larger than the remaining bytes: caught by the cheap guard.
        let mut bytes = alloc::vec![0xFF, 0xFF, 0xFF, 0xFF];
        let mut cursor = &bytes[..];
        assert!(
            LengthPrefixed::<alloc::vec::Vec<ZeroWidth>>::deserialize_from_narg(&mut cursor)
                .is_err()
        );
        assert_eq!(cursor, &bytes[..]);

        // Count within the remaining bytes, so the loop is entered: the
        // zero-width element is rejected on the first iteration.
        bytes = alloc::vec![8, 0, 0, 0];
        bytes.extend_from_slice(&[0u8; 8]);
        let mut cursor = &bytes[..];
        assert!(
            LengthPrefixed::<alloc::vec::Vec<ZeroWidth>>::deserialize_from_narg(&mut cursor)
                .is_err()
        );
        assert_eq!(cursor, &bytes[..]);

        // An empty sequence still parses: no element is ever read.
        let empty = [0u8, 0, 0, 0];
        let mut cursor = &empty[..];
        let LengthPrefixed(elements) =
            LengthPrefixed::<alloc::vec::Vec<ZeroWidth>>::deserialize_from_narg(&mut cursor)
                .unwrap();
        assert!(elements.is_empty());
        assert!(cursor.is_empty());
    }
}
