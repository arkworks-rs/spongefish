//! This module provides the encoding and decoding maps composing the codec.
//!
use crate::Unit;

pub trait Encoding<T: ?Sized> {
    fn encode(&self) -> impl AsRef<T>;
}

pub trait Decoding<T: ?Sized> {
    type Repr: Default + AsMut<T>;

    fn decode(buf: Self::Repr) -> Self;
}

impl<U: Unit> Encoding<[U]> for &[U] {
    fn encode(&self) -> impl AsRef<[U]> {
        self
    }
}

impl Encoding<[Self]> for u8 {
    fn encode(&self) -> impl AsRef<[Self]> {
        [*self]
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

impl Encoding<[u8]> for str {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_bytes()
    }
}
