//! A codec is a set of maps for encoding prover messages into inputs for the duplex sponge
//! and outputs to be re-mapped into verifier messages.
//!
//! # Derive Macros
//!
//! With the `derive` feature enabled:
//!
//! ```ignore
//! use spongefish::Codec;
//!
//! #[derive(Codec)]
//! struct MyStruct {
//!     field1: u32,
//!     field2: u64,
//!     #[spongefish(skip)]  // Skip this field (uses Default)
//!     cached: Option<String>,
//! }
//! ```
//!
//! Equivalent to deriving `Encoding`, `Decoding`, and `NargDeserialize`. Fields marked with
//! `#[spongefish(skip)]` are initialized via `Default`.

/// Marker trait for types that implement `Encoding<T>`, and `Decoding<T>`; `NargSerialize` and `NargDeserialize`
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
    /// # use spongefish::codecs::Decoding;
    /// assert_eq!(<u32 as Decoding<[u8]>>::Repr::default(), [0u8; 4])
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
        for element in self.iter() {
            output.extend_from_slice(element.encode().as_ref())
        }
        output
    }
}

impl Encoding<[u8]> for u32 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_be_bytes()
    }
}

impl Encoding<[u8]> for u64 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_be_bytes()
    }
}

impl Encoding<[u8]> for u128 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_be_bytes()
    }
}

impl Decoding<[u8]> for u32 {
    type Repr = [u8; 4];

    fn decode(buf: Self::Repr) -> Self {
        Self::from_be_bytes(buf)
    }
}

impl Decoding<[u8]> for u64 {
    type Repr = [u8; 8];

    fn decode(buf: Self::Repr) -> Self {
        Self::from_be_bytes(buf)
    }
}

impl Decoding<[u8]> for u128 {
    type Repr = [u8; 16];

    fn decode(buf: Self::Repr) -> Self {
        Self::from_be_bytes(buf)
    }
}

impl<const N: usize> Encoding<[u8]> for [u8; N] {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_slice()
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

impl Encoding<[u8]> for alloc::vec::Vec<u8> {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_slice()
    }
}

impl<U: Clone, T: Encoding<[U]>> Encoding<[U]> for alloc::vec::Vec<T> {
    fn encode(&self) -> impl AsRef<[U]> {
        let mut out = alloc::vec::Vec::new();
        for x in self.iter() {
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
