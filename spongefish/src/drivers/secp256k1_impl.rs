//! secp256k1 (k256) codec implementations
use k256::{
    elliptic_curve::{
        bigint::U512,
        ff::Field,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, ProjectivePoint, Scalar,
};

use crate::{
    codecs::{Decoding, Encoding},
    error::VerificationError,
    io::NargDeserialize,
    VerificationResult,
};

// Make k256 Scalar a valid Unit type
impl crate::Unit for Scalar {
    const ZERO: Self = <Scalar as Field>::ZERO;
}

// Implement Decoding for k256 Scalar
impl Decoding<[u8]> for Scalar {
    type Repr = super::Array64;

    fn decode(buf: Self::Repr) -> Self {
        use k256::elliptic_curve::{bigint::Encoding, ops::Reduce};
        Scalar::reduce(U512::from_le_bytes(buf.0))
    }
}

// Implement Deserialize for k256 Scalar
impl NargDeserialize for Scalar {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 32 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&buf[..32]);
        *buf = &buf[32..];

        use k256::elliptic_curve::ff::PrimeField;
        repr.reverse();
        Option::from(Scalar::from_repr(repr.into())).ok_or(VerificationError)
    }
}

// Implement Deserialize for ProjectivePoint
impl NargDeserialize for ProjectivePoint {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        // Compressed points are 33 bytes
        if buf.len() < 33 {
            return Err(VerificationError);
        }

        use k256::EncodedPoint;
        let encoded = EncodedPoint::from_bytes(&buf[..33]).map_err(|_| VerificationError)?;
        *buf = &buf[33..];
        Option::from(ProjectivePoint::from_encoded_point(&encoded)).ok_or(VerificationError)
    }
}

// Implement Encoding for k256 Scalar
impl Encoding<[u8]> for Scalar {
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        bytes
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
