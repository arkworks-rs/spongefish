//! BabyBear field codec implementation

use alloc::{vec, vec::Vec};

use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field, PrimeField32};

use super::common::{from_bytes_mod_order_u32, PlonkyFieldBuffer};
use crate::{
    codecs::{Decoding, Encoding},
    error::VerificationError,
    io::{Deserialize, Serialize},
    VerificationResult,
};

// BabyBear field modulus: 2^31 - 2^27 + 1 = 2013265921
const BABYBEAR_MODULUS: u32 = 2013265921;
const BABYBEAR_BITS: u32 = 31;

// Make BabyBear a valid Unit type
impl crate::Unit for BabyBear {
    const ZERO: Self = BabyBear::zero();
}

// Buffer for decoding BabyBear elements
pub struct BabyBearBuffer([u8; 20]);

impl Default for BabyBearBuffer {
    fn default() -> Self {
        BabyBearBuffer([0u8; 20])
    }
}

impl AsMut<[u8]> for BabyBearBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

// Implement Decoding for BabyBear
impl Decoding<[u8]> for BabyBear {
    type Repr = BabyBearBuffer;

    fn decode(buf: Self::Repr) -> Self {
        let value = BabyBear::from_be_bytes_mod_order(&buf.0 .0, BABYBEAR_MODULUS);
        BabyBear::from_canonical_u32(value)
    }
}

// Implement Deserialize for BabyBear
impl Deserialize for BabyBear {
    fn deserialize_from(buf: &[u8]) -> VerificationResult<Self> {
        if buf.len() < 4 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 4];
        repr.copy_from_slice(&buf[..4]);
        let value = u32::from_le_bytes(repr);

        // Check that the value is in the valid range
        if value >= BABYBEAR_MODULUS {
            return Err(VerificationError);
        }

        Ok(BabyBear::from_canonical_u32(value))
    }
}

// Implement Encoding for BabyBear
impl Encoding<[u8]> for BabyBear {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_canonical_u32().to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use p3_field::Field;

    use super::*;

    #[test]
    fn test_babybear_serialize_deserialize() {
        // Create a field element
        let element = BabyBear::from_canonical_u32(12345);

        let mut buf = Vec::new();
        element.serialize_into(&mut buf);

        let deserialized = BabyBear::deserialize_from(&buf).unwrap();
        assert_eq!(element, deserialized);
    }

    #[test]
    fn test_babybear_encoding() {
        let element = BabyBear::from_canonical_u32(67890);

        let encoded = element.encode();
        let encoded_bytes = encoded.as_ref();

        let deserialized = BabyBear::deserialize_from(encoded_bytes).unwrap();
        assert_eq!(element, deserialized);
    }

    #[test]
    fn test_babybear_decoding() {
        let buf = BabyBearBuffer::default();
        let decoded = BabyBear::decode(buf);
        assert_eq!(decoded, BabyBear::ZERO);
    }

    #[test]
    fn test_babybear_out_of_range() {
        // Try to deserialize a value larger than the modulus
        let buf = BABYBEAR_MODULUS.to_le_bytes();
        let result = BabyBear::deserialize_from(&buf);
        assert!(result.is_err());
    }
}
