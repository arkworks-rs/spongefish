//! Plonky3 `BabyBear` bindings: sponge `Unit` impl plus codec implementations.

use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;

use crate::{Decoding, Encoding, NargDeserialize, VerificationError, VerificationResult};

const BABYBEAR_ZERO: BabyBear = unsafe { core::mem::transmute(0u32) };

// Make BabyBear a valid Unit type
impl crate::Unit for BabyBear {
    const ZERO: Self = BABYBEAR_ZERO;
}

// Implement Decoding for BabyBear.
//
// Sampling 32 bits and reducing them modulo ORDER_U32 would give ~31.2 bits of
// indistinguishability. We instead sample 64 bits and reduce modulo ORDER_U32,
// giving ~64.3 bits.
impl Decoding<[u8]> for BabyBear {
    type Repr = [u8; 8];

    fn decode(buf: Self::Repr) -> Self {
        let n = u64::from_le_bytes(buf);
        Self::new((n % u64::from(Self::ORDER_U32)) as u32)
    }
}

impl NargDeserialize for BabyBear {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 4 {
            return Err(VerificationError);
        }

        let mut repr = [0u8; 4];
        repr.copy_from_slice(&buf[..4]);
        let value = u32::from_be_bytes(repr);

        if value >= Self::ORDER_U32 {
            return Err(VerificationError);
        }

        *buf = &buf[4..];
        Ok(Self::new(value))
    }
}

impl Encoding<[u8]> for BabyBear {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_canonical_u32().to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::NargSerialize;

    #[test]
    fn baby_bear_serialize_deserialize_roundtrips() {
        let element = BabyBear::new(12345);
        let mut buf = Vec::new();
        element.serialize_into_narg(&mut buf);

        let decoded = BabyBear::deserialize_from_narg(&mut &buf[..]).unwrap();
        assert_eq!(element, decoded);
    }

    #[test]
    fn baby_bear_rejects_out_of_range_encoding() {
        let buf = BabyBear::ORDER_U32.to_be_bytes();
        let before = &buf[..];
        let mut cursor = before;

        let result = BabyBear::deserialize_from_narg(&mut cursor);

        assert!(result.is_err());
        assert_eq!(cursor, before);
    }
}
