//! p256 codec implementations
use p256::{
    elliptic_curve::{
        ff::{FromUniformBytes, PrimeField},
        group::GroupEncoding,
        sec1::{FromSec1Point, ToSec1Point},
    },
    AffinePoint, ProjectivePoint, Scalar,
};

use crate::{
    codecs::{Decoding, Encoding},
    drivers::Array64,
    error::VerificationError,
    io::NargDeserialize,
    VerificationResult,
};

// Make p256 Scalar a valid Unit type
impl crate::Unit for Scalar {
    const ZERO: Self = Self::ZERO;
}

// Implement Decoding for p256 Scalar
impl Decoding<[u8]> for Scalar {
    type Repr = Array64;

    fn decode(buf: Self::Repr) -> Self {
        let mut x = buf.0;
        x.reverse();
        Self::from_uniform_bytes(&x)
    }
}

// Implement Deserialize for p256 Scalar
impl NargDeserialize for Scalar {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        let mut repr = <Self as PrimeField>::Repr::default();
        let n = repr.0.len();
        if buf.len() < n {
            return Err(VerificationError);
        }

        repr.copy_from_slice(&buf[..n]);
        *buf = &buf[n..];
        repr.reverse();
        Self::from_repr(repr).into_option().ok_or(VerificationError)
    }
}

// Implement Deserialize for ProjectivePoint
impl NargDeserialize for ProjectivePoint {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        let mut repr = <Self as GroupEncoding>::Repr::default();
        let n = repr.0.len();
        if buf.len() < n {
            return Err(VerificationError);
        }

        repr.copy_from_slice(&buf[..n]);
        *buf = &buf[n..];
        Self::from_sec1_bytes(&repr).map_err(|_| VerificationError)
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
        self.to_compressed_point()
    }
}

impl Encoding<[u8]> for AffinePoint {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_compressed_point()
    }
}
