//! Maps for encoding prover messages and decoding verifier messages.

/// Marker trait for types that have encoding and decoding maps.
///
/// A type is a [`Codec`] if it implements [`Encoding`], [`Decoding`],
/// [`NargSerialize`][crate::io::NargSerialize], and [`NargDeserialize`][crate::io::NargDeserialize]
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
/// `#[spongefish(skip)]` are initialized via `Default`.
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
/// [`Encoding`] must be **prefix-free**: the output of [`Encoding::encode`] is never a prefix of any other
/// instance of the same type.
///
/// More information on the theoretical requirements is in [[CO25], Theorem 6.2].
///
/// # Blanket implementations
///
/// # Encoding conventions
///
/// For byte sequences, encoding must be the identity function.
/// Integers are encoded via []
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

    ///  The distribution-preserving map, that re-maps a squeezed output [`Decoding::Repr`] into a verifier message.
    ///
    /// This map is not exactly a decoding function (e.g., it can be onto). What is demanded from this function is that
    /// it preserves the uniform distribution: if [`Decoding::Repr`] is distributed uniformly at random, the also the output of [`decode`][Decoding::decode] is so.
    fn decode(buf: Self::Repr) -> Self;
}

impl<U: Clone, T: Encoding<[U]>, const N: usize> Encoding<[U]> for [T; N] {
    fn encode(&self) -> impl AsRef<[U]> {
        let mut output = alloc::vec::Vec::new();
        for element in self {
            output.extend_from_slice(element.encode().as_ref());
        }
        output
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
/// Encoding functions must have size known upon choosing the protocol identifier.
/// While slices don't have size known at compile time, the burden of making sure that the string
/// is of the correct size is on the caller.
impl Encoding<[u8]> for [u8] {
    fn encode(&self) -> impl AsRef<[u8]> {
        self
    }
}

impl<const N: usize> Encoding<[u8]> for &[u8; N] {
    fn encode(&self) -> impl AsRef<[u8]> {
        *self
    }
}

impl<U: Clone, T: Encoding<[U]>> Encoding<[U]> for alloc::vec::Vec<T> {
    fn encode(&self) -> impl AsRef<[U]> {
        let mut out = alloc::vec::Vec::new();
        for x in self {
            out.extend_from_slice(x.encode().as_ref());
        }
        out
    }
}

impl<A, B> Encoding<[u8]> for (A, B)
where
    A: Encoding<[u8]>,
    B: Encoding<[u8]>,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut output = alloc::vec::Vec::new();
        output.extend_from_slice(self.0.encode().as_ref());
        output.extend_from_slice(self.1.encode().as_ref());
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
        let mut output = alloc::vec::Vec::new();
        output.extend_from_slice(self.0.encode().as_ref());
        output.extend_from_slice(self.1.encode().as_ref());
        output.extend_from_slice(self.2.encode().as_ref());
        output
    }
}

/// Handy for serializing byte strings.
///
/// Encoding functions must have size known upon choosing the protocol identifier.
/// While slices don't have size known at compile time, the burden of making sure that the string
/// is of the correct size is on the caller.
impl Encoding<[u8]> for &[u8] {
    fn encode(&self) -> impl AsRef<[u8]> {
        *self
    }
}

/// Blanket implementation of [`Codec`] for all traits implementing
/// [`NargSerialize`][`crate::NargSerialize`],
/// [`NargDeserialize`][`crate::NargSerialize`],
/// [`Encoding`], and [`Decoding`]
impl<T, E> Codec<T> for E
where
    T: ?Sized,
    E: crate::NargDeserialize + crate::NargSerialize + Encoding<T> + Decoding<T>,
{
}
