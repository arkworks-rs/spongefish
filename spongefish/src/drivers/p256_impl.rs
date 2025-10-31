//! p256 codec implementations
use digest::generic_array::GenericArray;
use k256::elliptic_curve::ops::ReduceNonZero;
use p256::{
    elliptic_curve::{
        bigint::U512,
        ff::Field,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, ProjectivePoint, Scalar,
};

use crate::{
    VerificationResult, codecs::{Decoding, Encoding}, drivers::Array64, error::VerificationError, io::NargDeserialize
};

// Make p256 Scalar a valid Unit type
impl crate::Unit for Scalar {
    const ZERO: Self = <Scalar as Field>::ZERO;
}

// Implement Decoding for p256 Scalar
impl Decoding<[u8]> for Scalar {
    type Repr = Array64;

    fn decode(buf: Self::Repr) -> Self {
        Scalar::reduce_nonzero_bytes(&buf.0.into())
    }
}

// Implement Deserialize for p256 Scalar
impl NargDeserialize for Scalar {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 32 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&buf[..32]);
        *buf = &buf[32..];

        use p256::elliptic_curve::ff::PrimeField;
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

        use p256::EncodedPoint;
        let encoded = EncodedPoint::from_bytes(&buf[..33]).map_err(|_| VerificationError)?;
        *buf = &buf[33..];
        Option::from(ProjectivePoint::from_encoded_point(&encoded)).ok_or(VerificationError)
    }
}

// Implement Encoding for p256 Scalar
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
