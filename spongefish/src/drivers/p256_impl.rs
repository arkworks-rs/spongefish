//! p256 bindings: sponge `Unit` impl plus codec implementations.

use p256::{
    AffinePoint, ProjectivePoint, Scalar, U256,
    elliptic_curve::{PrimeField, group::GroupEncoding, ops::Reduce, sec1::ToEncodedPoint},
};

use crate::{
    Decoding, Encoding, NargDeserialize, VerificationError, VerificationResult,
    drivers::Array64,
};

impl crate::Unit for Scalar {
    const ZERO: Self = Self::ZERO;
}

// Implement Decoding for p256 Scalar
impl Decoding<[u8]> for Scalar {
    type Repr = Array64;

    fn decode(buf: Self::Repr) -> Self {
        let mut hi = Self::reduce(U256::from_be_slice(&buf.0[0..32]));
        let lo = Self::reduce(U256::from_be_slice(&buf.0[32..64]));
        for _ in 0..256 {
            hi += hi;
        }
        hi + lo
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
