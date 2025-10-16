//! This module provides the encoding and decoding maps composing the codec.
//!
use crate::Unit;

pub trait Encodable<T: ?Sized> {
    fn encode(&self) -> impl AsRef<T>;
}

pub trait Decodable<T: ?Sized> {
    type Repr:  Default + AsMut<T>;

    fn decode(buf: Self::Repr) -> Self;
}

impl<U: Unit> Encodable<[U]> for &[U] {
    fn encode(&self) -> impl AsRef<[U]> {
        self
    }
}

impl Encodable<[u8]> for u8 {
    fn encode(&self) -> impl AsRef<[u8]> {
        [*self]
    }
}

impl Encodable<[u8]> for u32 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_be_bytes()
    }
}

impl Encodable<[u8]> for u64 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_be_bytes()
    }
}

impl Encodable<[u8]> for u128 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_be_bytes()
    }
}

impl Encodable<[u8]> for str {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_bytes()
    }
}

