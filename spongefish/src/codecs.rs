//! Maps for encoding prover messages and decoding verifier messages.

use alloc::vec::Vec;

/// Marker trait for types that have encoding and decoding maps.
///
/// A type is a [`Codec`] if it implements [`Encoding`], [`Decoding`],
/// and [`NargDeserialize`][crate::NargDeserialize].
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
pub trait Codec<T = [u8]>: crate::NargDeserialize + Encoding + Encoding<T> + Decoding<T>
where
    T: ?Sized,
{
}

/// A prefix-free map from a type into strings over a sponge alphabet.
///
/// The parameter `U` is the target alphabet, as a slice type. `Encoding<[U]>`
/// maps into a random oracle that operates over a [`Unit`][crate::Unit] `U`.
/// Its output is what will be absorbed. The default unit, `Encoding<[u8]>`, is
/// also the serialization written to the NARG string.
/// A type used with a sponge over another alphabet implements the trait once per alphabet;
/// see [Messages and codecs](crate#messages-and-codecs).
///
/// # Security
///
/// [`spongefish`][`crate`] assumes that prover and verifier will know the length of all the prover messages.
/// [`Encoding`] must be **prefix-free**: the output of [`Encoding::encode`] is never a prefix of the
/// encoding of any other instance of the same type.
///
/// Changing the encoding function requires changing the session identifier too.
///
///  More information on the theoretical requirements is in [[CO25], Theorem 6.2].
///
/// # Encoding conventions
///
/// Byte arrays `[u8; N]` encode as themselves; a bare `[u8]` has no encoding,
/// as it is not prefix-free (use [`LengthPrefixed`]).
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

/// A distribution-preserving map from squeezed sponge output to a verifier
/// message.
///
/// The parameter `T` is the sponge alphabet as a slice type, as for
/// [`Encoding`]: `Decoding<[U]>` reads a string over the alphabet of a sponge
/// whose [`Unit`][crate::Unit] is `U`, and the default `Decoding<[u8]>` serves
/// byte sponges. This is the map `ψ` of [[CO25], Definition 4.1]: the sponge
/// squeezes a uniformly random [`Decoding::Repr`], and
/// [`decode`][Decoding::decode] turns it into the message. The same map draws
/// the prover's private randomness
/// ([`PrivateRng::sample`][crate::PrivateRng::sample]), where a bias is worse
/// than a soundness loss: biased nonces leak the witness.
///
/// # Security
///
/// [`decode`][Decoding::decode] need not be injective, but it **must**
/// preserve the uniform distribution: for a uniform `Repr`, its output must
/// be uniform over the message type, or statistically close to it. [[CO25]]
/// calls that statistical distance the bias of the decoding map, and this distance
/// is part of the soundness and zero-knowledge bounds as an additive error term, so it
/// has to be negligible.
///
/// The width of `Repr` can help make the decoding bias negligible:
///
/// - A type with a power-of-two number of values, an integer `uN` or a byte
///   array, is decoded from a `Repr` of exactly its own width: the map is a
///   bijection and the bias is zero. The built-in codecs do this for [u8],
///   [u16], [u32], [u64], and [u128].
/// - An integer modulo `p`, a field element or a scalar, is decoded by
///   reducing a uniform `m`-bit integer modulo `p`. The bias of that
///   reduction is at most `2^-λ` once `m ≥ ⌈log₂ p⌉ + λ`
///   ([[CO25], Appendix C, Lemma C.1]), so squeeze `λ` bits more than `p`
///   occupies and reduce the whole string. This is `DecodeUint` of
///   draft-irtf-cfrg-fiat-shamir, whose `Ns + 16` bytes are `λ = 128`.
///   Reducing only as many bytes as `p` occupies is not safe in general: the
///   same lemma puts the bias at `2r(p − r) / (p · 2^m)` with `r = 2^m mod p`,
///   which is negligible only when `2^m` lies within a negligible fraction of
///   a multiple of `p`. It is about `2^-31` for the P-256 group order, and
///   about `0.15`, a constant, for the BLS12-381 scalar field.
///
/// On a byte sponge, `ByteArray<N>` is the `N`-byte `Repr`. The width is part
/// of the codec: prover and verifier must squeeze the same `Repr`, and a change
/// of width changes the transcript, so it must be reflected in the application
/// tag.
///
/// Changing the decoding function requires changing the session identifier too.
///
/// [CO25]: https://eprint.iacr.org/2025/536.pdf
pub trait Decoding<T = [u8]>
where
    T: ?Sized,
{
    /// The output type (and length) expected by the duplex sponge.
    ///
    /// The squeezed string over the alphabet, sized as described in the
    /// [security section](Decoding#security).
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

/// Arrays encode as the concatenation of their elements' encodings.
///
/// # Security
///
/// The concatenation is prefix-free because `N` is fixed by the type, so the
/// number of elements can never be chosen by the prover; for a length chosen at
/// run time, use [`LengthPrefixed`] instead. Each element's encoding must be
/// prefix-free on its own domain, which [`Encoding`] already requires.
impl<U: Clone, T: Encoding<[U]>, const N: usize> Encoding<[U]> for [T; N] {
    fn encode(&self) -> impl AsRef<[U]> {
        let mut output = Vec::new();
        if let Some(first) = self.first() {
            let head = first.encode();
            let head = head.as_ref();
            // Elements of an array share a type, and every codec in this crate
            // is fixed-width, so the first element's length times `N` is the
            // exact total: one allocation instead of `log2(N)` reallocations.
            // A variable-width element codec merely makes this a hint — the
            // vector still grows on its own, and the bytes are unchanged.
            output.reserve_exact(head.len().saturating_mul(N));
            // `head` again rather than re-encoding element 0.
            output.extend_from_slice(head);
            for element in &self[1..] {
                output.extend_from_slice(element.encode().as_ref());
            }
        }
        output
    }
}

macro_rules! impl_int_encoding {
    ($($type: ty),*) => {$(
        impl Encoding for $type {
            fn encode(&self) -> impl AsRef<[u8]> {
                self.to_le_bytes()
            }
        }

        impl Decoding for $type {
            type Repr = ByteArray<{ core::mem::size_of::<$type>() }>;

            fn decode(buf: Self::Repr) -> Self {
                <$type>::from_le_bytes(Decoding::decode(buf))
            }
        }
    )*};
}

impl_int_encoding!(u8, u16, u32, u64, u128);

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

impl<const N: usize> Decoding for [u8; N] {
    type Repr = ByteArray<N>;

    fn decode(buf: Self::Repr) -> Self {
        buf.0
    }
}

/// Handy for serializing UTF-8 strings.
///
/// Strings are encoded as their little-endian `u32` byte length followed by their UTF-8 bytes.
/// This makes the byte-oriented encoding prefix-free.
impl Encoding for str {
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

/// Tuples encode as the concatenation of their components' encodings.
///
/// # Security
///
/// The concatenation is prefix-free exactly when each component's encoding is,
/// which [`Encoding`] already requires. It does **not** hold for a tuple mixing
/// codecs of different alphabets or widths chosen at run time — the components
/// must each be prefix-free on their own domain.
macro_rules! impl_tuple_encoding {
    ($(($($param:ident $binding:ident $index:tt),+);)*) => {$(
        impl<$($param: Encoding),+> Encoding for ($($param,)+) {
            fn encode(&self) -> impl AsRef<[u8]> {
                let ($($binding,)+) = ($(self.$index.encode(),)+);
                let ($($binding,)+) = ($($binding.as_ref(),)+);
                let mut output = Vec::with_capacity(0 $(+ $binding.len())+);
                $(output.extend_from_slice($binding);)+
                output
            }
        }
    )*};
}

impl_tuple_encoding! {
    (A a 0, B b 1);
    (A a 0, B b 1, C c 2);
    (A a 0, B b 1, C c 2, D d 3);
    (A a 0, B b 1, C c 2, D d 3, E e 4);
    (A a 0, B b 1, C c 2, D d 3, E e 4, F f 5);
    (A a 0, B b 1, C c 2, D d 3, E e 4, F f 5, G g 6);
    (A a 0, B b 1, C c 2, D d 3, E e 4, F f 5, G g 6, H h 7);
}

/// A variable-length sequence, encoded with a `u32` element-count prefix.
///
/// ```
/// # #[cfg(all(feature = "turboshake128", feature = "getrandom"))]
/// # {
/// use spongefish::{Argument, LengthPrefixed, Narg, Transcript,
///                  VerificationError, Witness};
///
/// struct Sequence;
/// impl Argument for Sequence {
///     type Instance = u32;
///     type Witness = Vec<u32>;
///     type Output = Vec<u32>;
///
///     fn run<T: Transcript>(
///         transcript: &mut T,
///         _instance: &u32,
///         witness: Witness<&Vec<u32>>,
///     ) -> Result<Vec<u32>, VerificationError> {
///         let LengthPrefixed(values) = transcript.prover_message(
///             witness.map(|values| LengthPrefixed(values.clone())),
///         )?;
///         Ok(values)
///     }
/// }
///
/// let tag = b"examples/LengthPrefixed";
/// let values = vec![7u32, 8, 9];
/// let (narg, prover_output) = Narg::prove::<Sequence>(tag, &0, &values).unwrap();
/// assert_eq!(prover_output, values);
/// assert_eq!(Narg::verify::<Sequence>(tag, &0, &narg).unwrap(), values);
/// # }
/// ```
///
/// # Security
///
/// The count prefix makes the encoding prefix-free even when the sequence
/// length is not fixed by the protocol, but does not disambiguate the type or what the length indicates.
/// This information is part of the session identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthPrefixed<T>(pub T);

impl<T> LengthPrefixed<T> {
    /// Consumes the wrapper, returning the inner sequence.
    pub fn into_inner(self) -> T {
        self.0
    }
}

fn encode_length_prefixed<T: Encoding>(elements: &[T]) -> Vec<u8> {
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

impl<T: Encoding> Encoding for LengthPrefixed<&[T]> {
    fn encode(&self) -> impl AsRef<[u8]> {
        encode_length_prefixed(self.0)
    }
}

impl<T: Encoding> Encoding for LengthPrefixed<Vec<T>> {
    fn encode(&self) -> impl AsRef<[u8]> {
        encode_length_prefixed(&self.0)
    }
}

impl<T: crate::NargDeserialize> crate::NargDeserialize for LengthPrefixed<Vec<T>> {
    /// A truncated count and a zero-width element are failures of this codec
    /// itself, so the element error is folded into the same
    /// [`VerificationError`][crate::VerificationError].
    type Error = crate::VerificationError;

    fn deserialize_from_narg(reader: &mut crate::NargReader<'_>) -> Result<Self, Self::Error> {
        let len = reader.read::<u32>()? as usize;
        reader.read_vec(len).map(Self)
    }
}

/// Blanket implementation of [`Codec`] for all types implementing
/// [`NargDeserialize`][`crate::NargDeserialize`], [`Encoding`], and [`Decoding`].
impl<T, E> Codec<T> for E
where
    T: ?Sized,
    E: crate::NargDeserialize + Encoding + Encoding<T> + Decoding<T>,
{
}

#[cfg(test)]
mod tests {
    use super::{Encoding, LengthPrefixed, Vec};
    use crate::NargDeserialize;

    /// The `str` codec spans the inline/heap boundary as the string grows; the
    /// bytes must stay `u32` length prefix followed by UTF-8, throughout.
    #[test]
    fn str_encoding_is_stable_across_the_spill_boundary() {
        for len in [0usize, 1, 100, 123, 124, 125, 200, 1000] {
            let text = "x".repeat(len);
            let text = text.as_str();
            let encoded = Encoding::<[u8]>::encode(&text);
            let mut expected = Vec::new();
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
            let values: Vec<u32> = (0..len as u32).collect();
            let wrapper = LengthPrefixed(&values[..]);
            let encoded = wrapper.encode();
            let mut expected = Vec::new();
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

        let mut reader = crate::NargReader::new(bytes.as_ref());
        let LengthPrefixed(read_back) =
            LengthPrefixed::<Vec<u32>>::deserialize_from_narg(&mut reader).unwrap();
        assert_eq!(read_back, values);
        assert!(reader.is_empty());

        // Truncated element data is rejected.
        let truncated = &bytes.as_ref()[..bytes.as_ref().len() - 1];
        let mut reader = crate::NargReader::new(truncated);
        assert!(LengthPrefixed::<Vec<u32>>::deserialize_from_narg(&mut reader).is_err());

        // A huge count with no data behind it fails on the first element.
        let bogus = [0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = crate::NargReader::new(&bogus);
        assert!(LengthPrefixed::<Vec<u32>>::deserialize_from_narg(&mut reader).is_err());
    }

    /// An element codec whose encoded width depends on the *value*, not just
    /// the type. Contrived here, but not hypothetical: compressed SEC1 points
    /// encode the identity in one byte and every other point in 33.
    struct VariableWidth(usize);

    impl Encoding for VariableWidth {
        fn encode(&self) -> impl AsRef<[u8]> {
            alloc::vec![self.0 as u8; self.0]
        }
    }

    /// The array codec sizes its buffer from the first element's width. A
    /// variable-width codec must still produce the plain concatenation, whatever
    /// order the widths arrive in.
    #[test]
    fn array_encoding_handles_variable_width_elements() {
        let cases: [[VariableWidth; 4]; 5] = [
            // One unit first, then wider: the ordering that would truncate if
            // the hint were treated as the exact total.
            [
                VariableWidth(1),
                VariableWidth(3),
                VariableWidth(1),
                VariableWidth(2),
            ],
            // Wider first: the hint overshoots.
            [
                VariableWidth(3),
                VariableWidth(1),
                VariableWidth(1),
                VariableWidth(1),
            ],
            // Uniformly one unit: the hint is exact.
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
            let mut expected = Vec::new();
            for element in case {
                expected.extend_from_slice(element.encode().as_ref());
            }
            let encoded = Encoding::<[u8]>::encode(case);
            assert_eq!(
                encoded.as_ref(),
                &expected[..],
                "widths {:?}",
                case.iter().map(|e| e.0).collect::<Vec<_>>()
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
        type Error = crate::VerificationError;

        fn deserialize_from_narg(_reader: &mut crate::NargReader<'_>) -> Result<Self, Self::Error> {
            Ok(Self)
        }
    }

    /// A zero-width element type must not let an attacker-chosen count spin the
    /// parse loop: the first element that consumes nothing is rejected, so the
    /// work stays bounded by the remaining bytes.
    #[test]
    fn length_prefixed_rejects_zero_width_elements() {
        // A huge count with nothing behind it: the first element consumes
        // nothing and is rejected, so the loop never spins through the count.
        let mut bytes = alloc::vec![0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = crate::NargReader::new(&bytes);
        assert!(LengthPrefixed::<Vec<ZeroWidth>>::deserialize_from_narg(&mut reader).is_err());

        // A count with payload behind it is rejected on the first element all
        // the same: the elements would never consume the payload.
        bytes = alloc::vec![8, 0, 0, 0];
        bytes.extend_from_slice(&[0u8; 8]);
        let mut reader = crate::NargReader::new(&bytes);
        assert!(LengthPrefixed::<Vec<ZeroWidth>>::deserialize_from_narg(&mut reader).is_err());

        // An empty sequence still parses: no element is ever read.
        let empty = [0u8, 0, 0, 0];
        let mut reader = crate::NargReader::new(&empty);
        let LengthPrefixed(elements) =
            LengthPrefixed::<Vec<ZeroWidth>>::deserialize_from_narg(&mut reader).unwrap();
        assert!(elements.is_empty());
        assert!(reader.is_empty());
    }
}
