//! Plonky3's KoalaBear field codec implementation
use p3_field::{AbstractField, PrimeField32};
use p3_koala_bear::KoalaBear;

use crate::{
    codecs::{Decoding, Encoding},
    io::NargDeserialize,
    VerificationError, VerificationResult,
};

const KOALABEAR_ZERO: KoalaBear = unsafe { core::mem::transmute(0u32) };

// Make KoalaBear a valid Unit type
impl crate::Unit for KoalaBear {
    const ZERO: Self = KOALABEAR_ZERO;
}

// Implement Decoding for KoalaBear
//
// Following the same reasoning as BabyBear:
// We use [u8; 8] (64 bits) and reduce modulo ORDER_U32
// to get sufficient indistinguishability.
//
// For KoalaBear with modulus 2^31 - 2^24 + 1 = 2,130,706,433:
// - Sampling 32 bits would give us ~31.2 bits of indistinguishability (weak)
// - Sampling 64 bits gives us ~64.3 bits of indistinguishability (sufficient)
impl Decoding<[u8]> for KoalaBear {
    type Repr = [u8; 8];

    fn decode(buf: Self::Repr) -> Self {
        let n = u64::from_le_bytes(buf);
        KoalaBear::from_canonical_u64(n % KoalaBear::ORDER_U32 as u64)
    }
}

// Implement Deserialize for KoalaBear
impl NargDeserialize for KoalaBear {
    fn deserialize_from(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 4 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 4];
        repr.copy_from_slice(&buf[..4]);
        let value = u32::from_le_bytes(repr);

        // Check that the value is in the valid range
        if value >= KoalaBear::ORDER_U32 {
            return Err(VerificationError);
        }

        *buf = &buf[4..];
        Ok(KoalaBear::from_canonical_u32(value))
    }
}

// Implement Encoding for KoalaBear
impl Encoding<[u8]> for KoalaBear {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_canonical_u32().to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use p3_field::Field;

    use super::*;
    use crate::io::NargSerialize;

    #[test]
    fn test_koalabear_serialize_deserialize() {
        // Create a field element
        let element = KoalaBear::from_canonical_u32(12345);

        let mut buf = Vec::new();
        element.serialize_into(&mut buf);

        let deserialized = KoalaBear::deserialize_from(&mut &buf[..]).unwrap();
        assert_eq!(element, deserialized);
    }

    #[test]
    fn test_koalabear_encoding() {
        let element = KoalaBear::from_canonical_u32(67890);

        let encoded = element.encode();
        let encoded_bytes = encoded.as_ref();

        let deserialized = KoalaBear::deserialize_from(&mut &encoded_bytes[..]).unwrap();
        assert_eq!(element, deserialized);
    }

    #[test]
    fn test_koalabear_out_of_range() {
        // Try to deserialize a value larger than the modulus
        let buf = KoalaBear::ORDER_U32.to_le_bytes();
        let result = KoalaBear::deserialize_from(&mut &buf[..]);
        assert!(result.is_err());
    }
}
