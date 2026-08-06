//! p256 codec implementations

use p256::{
    elliptic_curve::{group::GroupEncoding, ops::Reduce, sec1::ToEncodedPoint, PrimeField},
    AffinePoint, ProjectivePoint, Scalar, U256,
};

use crate::{
    codecs::{Decoding, Encoding},
    drivers::Array48,
    error::VerificationError,
    io::NargDeserialize,
    VerificationResult,
};

/// `2^128` as a 256-bit integer, used to recombine the two halves of the
/// little-endian wide reduction: `2^256 mod p = (2^128 mod p)^2`.
const TWO_POW_128: U256 =
    U256::from_be_hex("0000000000000000000000000000000100000000000000000000000000000000");

// Make p256 Scalar a valid Unit type
impl crate::Unit for Scalar {
    const ZERO: Self = Self::ZERO;
}

// Implement Decoding for p256 Scalar: the `DecodeField` of
// draft-irtf-cfrg-fiat-shamir. The 48-byte squeeze output is interpreted as a
// little-endian integer (LE2IP) and reduced mod p.
impl Decoding<[u8]> for Scalar {
    type Repr = Array48;

    fn decode(buf: Self::Repr) -> Self {
        // buf = lo (low 32 bytes, LE) + 2^256 * hi (high 16 bytes, LE)
        let lo = Self::reduce(U256::from_le_slice(&buf.0[0..32]));
        let mut hi_bytes = [0u8; 32];
        hi_bytes[..16].copy_from_slice(&buf.0[32..48]);
        // hi < 2^128 < p, so the reduction is the canonical injection.
        let hi = Self::reduce(U256::from_le_slice(&hi_bytes));
        let two_pow_128 = Self::reduce(TWO_POW_128);
        hi * two_pow_128 * two_pow_128 + lo
    }
}

// Implement Deserialize for p256 Scalar using OS2IP (big-endian)
impl NargDeserialize for Scalar {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        let mut repr = <Self as PrimeField>::Repr::default();
        let n = repr.len();
        if buf.len() < n {
            return Err(VerificationError);
        }

        repr.copy_from_slice(&buf[..n]);
        Self::from_repr(repr)
            .into_option()
            .inspect(|_| *buf = &buf[n..])
            .ok_or(VerificationError)
    }
}

// Implement Deserialize for ProjectivePoint
impl NargDeserialize for ProjectivePoint {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        let mut repr = <Self as GroupEncoding>::Repr::default();
        let n = repr.len();
        if buf.len() < n {
            return Err(VerificationError);
        }

        repr.copy_from_slice(&buf[..n]);
        Self::from_bytes(&repr)
            .into_option()
            .inspect(|_| *buf = &buf[n..])
            .ok_or(VerificationError)
    }
}

// Implement Encoding for p256 Scalar using I2OSP (big-endian)
impl Encoding<[u8]> for Scalar {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_bytes()
    }
}

// Implement Encoding for ProjectivePoint
impl Encoding<[u8]> for ProjectivePoint {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_encoded_point(true)
    }
}

impl Encoding<[u8]> for AffinePoint {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_encoded_point(true)
    }
}
