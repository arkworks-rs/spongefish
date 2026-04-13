//! Plonky3's Mersenne31 field codec implementation

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_mersenne_31::Mersenne31;

use crate::{
    codecs::{Decoding, Encoding},
    io::NargDeserialize,
    VerificationError, VerificationResult,
};

const MERSENNE31_ZERO: Mersenne31 = unsafe { core::mem::transmute(0u32) };

impl crate::Unit for Mersenne31 {
    const ZERO: Self = MERSENNE31_ZERO;
}

impl Decoding<[u8]> for Mersenne31 {
    type Repr = [u8; 8];

    fn decode(buf: Self::Repr) -> Self {
        let n = u64::from_le_bytes(buf);
        Self::from_u64(n % u64::from(Self::ORDER_U32))
    }
}

impl NargDeserialize for Mersenne31 {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 4 {
            return Err(VerificationError);
        }

        let mut repr = [0u8; 4];
        repr.copy_from_slice(&buf[..4]);
        let value = u32::from_be_bytes(repr);

        // Check that the value is in the valid range
        if value >= Self::ORDER_U32 {
            return Err(VerificationError);
        }
        *buf = &buf[4..];
        Ok(Self::from_u32(value))
    }
}

impl Encoding<[u8]> for Mersenne31 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_canonical_u32().to_be_bytes()
    }
}
