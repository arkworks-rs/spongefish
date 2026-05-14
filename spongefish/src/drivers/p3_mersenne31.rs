//! Plonky3 `Mersenne31` bindings: sponge `Unit` impl plus codec implementations.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_mersenne_31::Mersenne31;

use crate::{Decoding, Encoding, NargDeserialize, VerificationError, VerificationResult};

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

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::NargSerialize;

    #[test]
    fn mersenne31_serialize_deserialize_roundtrips() {
        let element = Mersenne31::from_u32(13579);
        let mut buf = Vec::new();
        element.serialize_into_narg(&mut buf);

        let decoded = Mersenne31::deserialize_from_narg(&mut &buf[..]).unwrap();
        assert_eq!(element, decoded);
    }

    #[test]
    fn mersenne31_rejects_out_of_range_encoding() {
        let buf = Mersenne31::ORDER_U32.to_be_bytes();
        let before = &buf[..];
        let mut cursor = before;

        let result = Mersenne31::deserialize_from_narg(&mut cursor);

        assert!(result.is_err());
        assert_eq!(cursor, before);
    }
}
