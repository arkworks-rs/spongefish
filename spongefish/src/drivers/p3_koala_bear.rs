//! Plonky3 `KoalaBear` bindings: sponge `Unit` impl plus codec implementations.

use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;

use crate::{Decoding, Encoding, NargDeserialize, VerificationError, VerificationResult};

const KOALABEAR_ZERO: KoalaBear = unsafe { core::mem::transmute(0u32) };

// Make KoalaBear a valid Unit type
impl crate::Unit for KoalaBear {
    const ZERO: Self = KOALABEAR_ZERO;
}

impl Decoding<[u8]> for KoalaBear {
    type Repr = [u8; 8];

    fn decode(buf: Self::Repr) -> Self {
        let n = u64::from_le_bytes(buf);
        Self::new((n % u64::from(Self::ORDER_U32)) as u32)
    }
}

impl NargDeserialize for KoalaBear {
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

impl Encoding<[u8]> for KoalaBear {
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
    fn koala_bear_serialize_deserialize_roundtrips() {
        let element = KoalaBear::new(67890);
        let mut buf = Vec::new();
        element.serialize_into_narg(&mut buf);

        let decoded = KoalaBear::deserialize_from_narg(&mut &buf[..]).unwrap();
        assert_eq!(element, decoded);
    }

    #[test]
    fn koala_bear_rejects_out_of_range_encoding() {
        let buf = KoalaBear::ORDER_U32.to_be_bytes();
        let before = &buf[..];
        let mut cursor = before;

        let result = KoalaBear::deserialize_from_narg(&mut cursor);

        assert!(result.is_err());
        assert_eq!(cursor, before);
    }
}
