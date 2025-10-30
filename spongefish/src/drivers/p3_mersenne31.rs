//! Plonky3's Mersenne31 field codec implementation

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_mersenne_31::Mersenne31;

use crate::{
    codecs::{Decoding, Encoding},
    io::NargDeserialize,
    VerificationError, VerificationResult,
};

const KOALABEAR_ZERO: Mersenne31 = unsafe { core::mem::transmute(0u32) };

impl crate::Unit for Mersenne31 {
    const ZERO: Self = KOALABEAR_ZERO;
}

impl Decoding<[u8]> for Mersenne31 {
    type Repr = [u8; 8];

    fn decode(buf: Self::Repr) -> Self {
        let n = u64::from_le_bytes(buf);
        return Mersenne31::from_u64(n % (Mersenne31::ORDER_U32 as u64));
    }
}

impl NargDeserialize for Mersenne31 {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 4 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 4];
        repr.copy_from_slice(&buf[..4]);
        let value = u32::from_le_bytes(repr);

        // Check that the value is in the valid range
        if value >= Mersenne31::ORDER_U32 {
            return Err(VerificationError);
        }

        Ok(Mersenne31::from_u32(value))
    }
}

impl Encoding<[u8]> for Mersenne31 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_canonical_u32().to_le_bytes()
    }
}
