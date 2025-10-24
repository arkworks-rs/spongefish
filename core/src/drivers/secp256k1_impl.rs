//! secp256k1 (k256) codec implementations
use k256::{
    elliptic_curve::{
        bigint::U512,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, ProjectivePoint, Scalar,
};

use crate::{
    codecs::{Decoding, Encoding},
    error::VerificationError,
    io::Deserialize,
    VerificationResult,
};

// Implement Decoding for k256 Scalar
impl Decoding<[u8]> for Scalar {
    type Repr = super::Slice64;

    fn decode(buf: Self::Repr) -> Self {
        use k256::elliptic_curve::{bigint::Encoding, ops::Reduce};
        Scalar::reduce(U512::from_le_bytes(buf.0))
    }
}

// Implement Deserialize for k256 Scalar
impl Deserialize for Scalar {
    fn deserialize_from(buf: &[u8]) -> VerificationResult<Self> {
        if buf.len() < 32 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&buf[..32]);

        use k256::elliptic_curve::ff::PrimeField;
        Option::from(Scalar::from_repr(repr.into())).ok_or(VerificationError)
    }
}

// Implement Deserialize for ProjectivePoint
impl Deserialize for ProjectivePoint {
    fn deserialize_from(buf: &[u8]) -> VerificationResult<Self> {
        if buf.len() < 33 {
            return Err(VerificationError);
        }

        use k256::EncodedPoint;
        let encoded = EncodedPoint::from_bytes(buf).map_err(|_| VerificationError)?;
        Option::from(ProjectivePoint::from_encoded_point(&encoded)).ok_or(VerificationError)
    }
}

// Implement Encoding for k256 Scalar
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
    use k256::elliptic_curve::ff::Field;

    use super::*;

    #[test]
    fn test_scalar_serialize_deserialize() {
        let scalar = Scalar::random(&mut rand::thread_rng());

        let mut buf = Vec::new();
        scalar.serialize_into(&mut buf);

        let deserialized = Scalar::deserialize_from(&buf).unwrap();
        assert_eq!(scalar, deserialized);
    }

    #[test]
    fn test_point_serialize_deserialize() {
        use k256::elliptic_curve::Group;

        let point = ProjectivePoint::random(&mut rand::thread_rng());

        let mut buf = Vec::new();
        point.serialize_into(&mut buf);

        let deserialized = ProjectivePoint::deserialize_from(&buf).unwrap();
        assert_eq!(point, deserialized);
    }

    #[test]
    fn test_scalar_encoding() {
        let scalar = Scalar::random(&mut rand::thread_rng());

        let encoded = scalar.encode();
        let encoded_bytes = encoded.as_ref();

        let deserialized = Scalar::deserialize_from(encoded_bytes).unwrap();
        assert_eq!(scalar, deserialized);
    }

    #[test]
    fn test_decoding() {
        let buf = Secp256k1ScalarBuffer::default();
        let scalar = Scalar::decode(buf);
        assert_eq!(scalar, Scalar::ZERO);
    }
}
