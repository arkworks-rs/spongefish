//! BLS12-381 codec implementations
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

use crate::{
    codecs::{Decoding, Encoding},
    error::VerificationError,
    io::NargDeserialize,
    VerificationResult,
};

// Make BLS12-381 scalar a valid Unit type
impl crate::Unit for Scalar {
    const ZERO: Self = Scalar::zero();
}

// Implement Decoding for curve25519-dalek Scalar
impl Decoding<[u8]> for Scalar {
    type Repr = super::Array64;

    fn decode(buf: Self::Repr) -> Self {
        Scalar::from_bytes_wide(&buf.0)
    }
}

// Implement Deserialize for BLS12-381 Scalar
impl NargDeserialize for Scalar {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 32 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&buf[..32]);
        *buf = &buf[32..];
        Option::from(Scalar::from_bytes(&repr)).ok_or(VerificationError)
    }
}

// Implement Deserialize for G1Projective
impl NargDeserialize for G1Projective {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        // G1 compressed points are 48 bytes
        if buf.len() < 48 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 48];
        repr.copy_from_slice(&buf[..48]);
        *buf = &buf[48..];

        let ct_option = G1Affine::from_compressed(&repr);
        if bool::from(ct_option.is_some()) {
            Ok(G1Projective::from(ct_option.unwrap()))
        } else {
            Err(VerificationError)
        }
    }
}

// Implement Deserialize for G2Projective
impl NargDeserialize for G2Projective {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        // G2 compressed points are 96 bytes
        if buf.len() < 96 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 96];
        repr.copy_from_slice(&buf[..96]);
        *buf = &buf[96..];

        let ct_option = G2Affine::from_compressed(&repr);
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
        G1Affine::from(self).to_compressed()
    }
}

// Implement Encoding for G2Projective
impl Encoding<[u8]> for G2Projective {
    fn encode(&self) -> impl AsRef<[u8]> {
        G2Affine::from(self).to_compressed()
    }
}
