//! BLS12-381 codec implementations
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::{ff::Field, GroupEncoding};

use crate::{
    codecs::{Decoding, Encoding},
    error::VerificationError,
    io::Deserialize,
    VerificationResult,
};

// Make BLS12-381 scalar a valid Unit type
impl crate::Unit for Scalar {
    const ZERO: Self = <Scalar as Field>::ZERO;
}

// Implement Decoding for curve25519-dalek Scalar
impl Decoding<[u8]> for Scalar {
    type Repr = super::Slice64;

    fn decode(buf: Self::Repr) -> Self {
        Scalar::from_bytes_wide(&buf.0)
    }
}

// Implement Deserialize for BLS12-381 Scalar
impl Deserialize for Scalar {
    fn deserialize_from(buf: &[u8]) -> VerificationResult<Self> {
        if buf.len() < 32 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&buf[..32]);
        Option::from(Scalar::from_bytes(&repr)).ok_or(VerificationError)
    }
}

// Implement Deserialize for G1Projective
impl Deserialize for G1Projective {
    fn deserialize_from(buf: &[u8]) -> VerificationResult<Self> {
        // G1 compressed points are 48 bytes
        let ct_option = G1Affine::from_compressed(buf.try_into().map_err(|_| VerificationError)?);
        if bool::from(ct_option.is_some()) {
            Ok(G1Projective::from(ct_option.unwrap()))
        } else {
            Err(VerificationError)
        }
    }
}

// Implement Deserialize for G2Projective
impl Deserialize for G2Projective {
    fn deserialize_from(buf: &mut &[u8]) -> VerificationResult<Self> {
        // G2 compressed points are 96 bytes
        let ct_option = G2Affine::from_compressed(buf.try_into().map_err(|_| VerificationError)?);
        if bool::from(ct_option.is_some()) {
            Ok(G2Projective::from(ct_option.unwrap()))
        } else {
            Err(VerificationError)
        }
    }
}

// Implement Encoding for BLS12-381 Scalar
impl Encoding<[u8]> for Scalar {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_bytes()
    }
}

// Implement Encoding for G1Projective
impl Encoding<[u8]> for G1Projective {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_bytes()
    }
}

// Implement Encoding for G2Projective
impl Encoding<[u8]> for G2Projective {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_bytes()
    }
}
