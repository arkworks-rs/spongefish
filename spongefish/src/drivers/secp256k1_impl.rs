//! secp256k1 (k256) codec implementations
use k256::{
    elliptic_curve::{
        bigint::U512,
        ff::{Field, PrimeField},
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
};

use crate::{
    codecs::{Decoding, Encoding},
    error::VerificationError,
    io::NargDeserialize,
    VerificationResult,
};

// Make k256 Scalar a valid Unit type
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

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::io::NargSerialize;

    #[test]
    fn test_scalar_serialize_deserialize() {
        let scalar = Scalar::random(&mut rand::thread_rng());

        let mut buf = Vec::new();
        scalar.serialize_into_narg(&mut buf);

        let mut buf_slice = &buf[..];
        let deserialized = Scalar::deserialize_from_narg(&mut buf_slice).unwrap();
        assert_eq!(scalar, deserialized);
    }

    #[test]
    fn test_point_serialize_deserialize() {
        use k256::elliptic_curve::Group;

        let point = ProjectivePoint::random(&mut rand::thread_rng());

        let mut buf = Vec::new();
        point.serialize_into_narg(&mut buf);

        let mut buf_slice = &buf[..];
        let deserialized = ProjectivePoint::deserialize_from_narg(&mut buf_slice).unwrap();
        assert_eq!(point, deserialized);
    }

    #[test]
    fn test_scalar_encoding() {
        let scalar = Scalar::random(&mut rand::thread_rng());

        let encoded = scalar.encode();
        let encoded_bytes = encoded.as_ref();

        let mut buf_slice = encoded_bytes;
        let deserialized = Scalar::deserialize_from_narg(&mut buf_slice).unwrap();
        assert_eq!(scalar, deserialized);
    }

    #[test]
    fn test_decoding() {
        let buf = super::super::Array64::default();
        let scalar = Scalar::decode(buf);
        assert_eq!(scalar, Scalar::ZERO);
    }
}
