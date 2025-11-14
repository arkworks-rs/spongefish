//! curve25519-dalek codec implementations
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

use crate::{
    codecs::{Decoding, Encoding},
    error::VerificationError,
    io::NargDeserialize,
    VerificationResult,
};

// Make curve25519-dalek Scalar a valid Unit type
impl crate::Unit for Scalar {
    const ZERO: Self = Scalar::ZERO;
}

// Implement Decoding for curve25519-dalek Scalar
impl Decoding<[u8]> for Scalar {
    type Repr = super::Array64;

    fn decode(buf: Self::Repr) -> Self {
        Scalar::from_bytes_mod_order_wide(&buf.0)
    }
}

impl Decoding<[u8]> for RistrettoPoint {
    type Repr = super::Array64;

    fn decode(buf: Self::Repr) -> Self {
        RistrettoPoint::from_uniform_bytes(&buf.0)
    }
}

// Implement Deserialize for curve25519-dalek Scalar
impl NargDeserialize for Scalar {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 32 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&buf[..32]);

        // from_canonical_bytes returns CtOption<Scalar>
        let ct_option = Scalar::from_canonical_bytes(repr);
        if bool::from(ct_option.is_some()) {
            *buf = &buf[32..];
            Ok(ct_option.unwrap())
        } else {
            Err(VerificationError)
        }
    }
}

// Implement Deserialize for EdwardsPoint
impl NargDeserialize for EdwardsPoint {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 32 {
            return Err(VerificationError);
        }
        let (head, tail) = buf.split_at(32);
        *buf = tail;
        CompressedEdwardsY(head.try_into().unwrap())
            .decompress()
            .ok_or(VerificationError)
    }
}

// Implement Deserialize for RistrettoPoint
impl NargDeserialize for RistrettoPoint {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 32 {
            return Err(VerificationError);
        }
        let (head, tail) = buf.split_at(32);
        *buf = tail;
        CompressedRistretto(head.try_into().unwrap())
            .decompress()
            .ok_or(VerificationError)
    }
}

// Implement Encoding for curve25519-dalek Scalar
impl Encoding<[u8]> for Scalar {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_bytes()
    }
}

// Implement Encoding for EdwardsPoint
impl Encoding<[u8]> for EdwardsPoint {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.compress().to_bytes()
    }
}

// Implement Encoding for RistrettoPoint
impl Encoding<[u8]> for RistrettoPoint {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.compress().to_bytes()
    }
}
