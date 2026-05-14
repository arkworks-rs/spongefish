//! secp256k1 (k256) bindings: sponge `Unit` impl plus codec implementations.

use k256::{
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        bigint::U512,
        ff::{Field, PrimeField},
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};

use crate::{Decoding, Encoding, NargDeserialize, VerificationError, VerificationResult};

impl crate::Unit for Scalar {
    const ZERO: Self = <Self as Field>::ZERO;
}

// Implement Decoding for k256 Scalar
impl Decoding<[u8]> for Scalar {
    type Repr = super::Array64;

    fn decode(buf: Self::Repr) -> Self {
        use k256::elliptic_curve::ops::Reduce;
        Self::reduce(U512::from_be_slice(&buf.0))
    }
}

// Implement Deserialize for k256 Scalar using OS2IP (big-endian)
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
        // Compressed points are 33 bytes
        if buf.len() < 33 {
            return Err(VerificationError);
        }

        let encoded = EncodedPoint::from_bytes(&buf[..33]).map_err(|_| VerificationError)?;
        let point = Option::from(Self::from_encoded_point(&encoded)).ok_or(VerificationError)?;
        *buf = &buf[33..];
        Ok(point)
    }
}

// Implement Encoding for k256 Scalar using I2OSP (big-endian)
impl Encoding<[u8]> for Scalar {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_bytes()
    }
}

// Implement Encoding for ProjectivePoint
impl Encoding<[u8]> for ProjectivePoint {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_affine().to_encoded_point(true)
    }
}

impl Encoding<[u8]> for AffinePoint {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_encoded_point(true)
    }
}
