//! A codec is a set of maps for encoding prover messages into inputs for the duplex sponge
//! and outputs to be re-mapped into verifier messages.
//!
//! # Derive Macros
//!
//! With the `derive` feature enabled:
//!
//! ```ignore
//! use spongefish::{Encoding, Decoding, NargDeserialize};
//!
//! #[derive(Encoding, Decoding, NargDeserialize)]
//! struct MyStruct {
//!     field1: u32,
//!     field2: u64,
//!     #[spongefish(skip)]  // Skip this field (uses Default)
//!     cached: Option<String>,
//! }
//! ```
//!
//! - `Encoding`: Encodes fields sequentially
//! - `Decoding`: Decodes from fixed-size buffer
//! - `NargDeserialize`: Deserializes from byte stream

/// Marker trait for types that implement `Encoding<T>`, and `Decoding<T>`; `NargSerialize` and `NargDeserialize`
pub trait Codec<T = [u8]>:
    crate::NargDeserialize + crate::NargSerialize + Encoding<T> + Decoding<T>
where
    T: ?Sized,
{
}

/// The interface for all prover messages that can be turned into an input for the duplex sponge.
///
/// Byte-oriented sponges can enjoy built-in maps for strings, bytes and built-in integer types. Integers are encoded in big-endian format.
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
