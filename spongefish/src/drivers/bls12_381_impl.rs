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
    const ZERO: Self = Self::zero();
}

// Implement Decoding for curve25519-dalek Scalar
impl Decoding<[u8]> for Scalar {
    type Repr = super::Array64;

    fn decode(buf: Self::Repr) -> Self {
        let mut wide = buf.0;
        wide.reverse();
        Self::from_bytes_wide(&wide)
    }
}

// Implement Deserialize for BLS12-381 Scalar using OS2IP (big-endian)
impl NargDeserialize for Scalar {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        const N: usize = 32;
        if buf.len() < N {
            return Err(VerificationError);
        }

        let be_bytes = &buf[..N];
        let mut le_bytes = [0u8; N];
        le_bytes.copy_from_slice(be_bytes);
        le_bytes.reverse();
        Self::from_bytes(&le_bytes)
            .into_option()
            .inspect(|_| *buf = &buf[N..])
            .ok_or(VerificationError)
    }
}

// Implement Deserialize for G1Projective
impl NargDeserialize for G1Projective {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        // G1 compressed points are 48 bytes
        const N: usize = 48;
        if buf.len() < N {
            return Err(VerificationError);
        }

        let mut repr = [0u8; N];
        repr.copy_from_slice(&buf[..N]);
        G1Affine::from_compressed(&repr)
            .into_option()
            .map(core::convert::Into::into)
            .inspect(|_| *buf = &buf[N..])
            .ok_or(VerificationError)
    }
}

// Implement Deserialize for G2Projective
impl NargDeserialize for G2Projective {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        // G2 compressed points are 96 bytes
        const N: usize = 96;
        if buf.len() < N {
            return Err(VerificationError);
        }

        let mut repr = [0u8; N];
        repr.copy_from_slice(&buf[..N]);
        G2Affine::from_compressed(&repr)
            .into_option()
            .map(core::convert::Into::into)
            .inspect(|_| *buf = &buf[N..])
            .ok_or(VerificationError)
    }
}

// Implement Encoding for BLS12-381 Scalar using I2OSP (big-endian)
impl Encoding<[u8]> for Scalar {
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut le_bytes = self.to_bytes();
        le_bytes.reverse();

        le_bytes
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
