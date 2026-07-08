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
    const ZERO: Self = Self::ZERO;
}

// Implement Decoding for curve25519-dalek Scalar: the `DecodeField` of
// draft-irtf-cfrg-fiat-shamir. The 48-byte squeeze output is interpreted as a
// little-endian integer (LE2IP) and reduced mod p.
impl Decoding<[u8]> for Scalar {
    type Repr = super::Array48;

    fn decode(buf: Self::Repr) -> Self {
        let mut wide = [0u8; 64];
        wide[..48].copy_from_slice(&buf.0);
        Self::from_bytes_mod_order_wide(&wide)
    }
}

impl Decoding<[u8]> for RistrettoPoint {
    type Repr = super::Array64;

    fn decode(buf: Self::Repr) -> Self {
        Self::from_uniform_bytes(&buf.0)
    }
}

// Implement Deserialize for curve25519-dalek Scalar using the curve25519
// family's canonical little-endian serialization (RFC 7748 / RFC 8032
// convention, as required by draft-irtf-cfrg-fiat-shamir for fields with a
// standard serialization).
impl NargDeserialize for Scalar {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        const N: usize = 32;
        if buf.len() < N {
            return Err(VerificationError);
        }

        let mut le_bytes = [0u8; N];
        le_bytes.copy_from_slice(&buf[..N]);
        Self::from_canonical_bytes(le_bytes)
            .into_option()
            .inspect(|_| *buf = &buf[N..])
            .ok_or(VerificationError)
    }
}

// Implement Deserialize for EdwardsPoint
impl NargDeserialize for EdwardsPoint {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 32 {
            return Err(VerificationError);
        }
        let point = CompressedEdwardsY(buf[..32].try_into().unwrap())
            .decompress()
            .ok_or(VerificationError)?;
        *buf = &buf[32..];
        Ok(point)
    }
}

// Implement Deserialize for RistrettoPoint
impl NargDeserialize for RistrettoPoint {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 32 {
            return Err(VerificationError);
        }
        let point = CompressedRistretto(buf[..32].try_into().unwrap())
            .decompress()
            .ok_or(VerificationError)?;
        *buf = &buf[32..];
        Ok(point)
    }
}

// Implement Encoding for curve25519-dalek Scalar using the canonical
// little-endian serialization of the curve25519 family.
impl Encoding<[u8]> for Scalar {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_bytes()
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
