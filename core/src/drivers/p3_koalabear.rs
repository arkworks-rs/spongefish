//! KoalaBear (Mersenne31) field codec implementation

use p3_field::{AbstractField, PrimeField32};
use p3_mersenne_31::Mersenne31;

use crate::{
    codecs::{Decoding, Encoding},
    error::VerificationError,
    io::Deserialize,
    VerificationResult,
};

// KoalaBear field modulus: 2^31 - 1 = 2147483647
const KOALABEAR_MODULUS: u32 = 2147483647;
const KOALABEAR_BITS: u32 = 31;

// Make KoalaBear/Mersenne31 a valid Unit type
impl crate::Unit for Mersenne31 {
    const ZERO: Self = Mersenne31::new(0);
}

// Buffer for decoding KoalaBear elements
pub struct KoalaBearBuffer(PlonkyFieldBuffer);

impl Default for KoalaBearBuffer {
    fn default() -> Self {
        KoalaBearBuffer(PlonkyFieldBuffer::new(KOALABEAR_BITS))
    }
}

impl AsMut<[u8]> for KoalaBearBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

// Implement Decoding for Mersenne31 (KoalaBear)
impl Decoding<[u8]> for Mersenne31 {
    type Repr = KoalaBearBuffer;

    fn decode(buf: Self::Repr) -> Self {
        let value = from_bytes_mod_order_u32(&buf.0 .0, KOALABEAR_MODULUS);
        Mersenne31::from_canonical_u32(value)
    }
}

// Implement Deserialize for Mersenne31 (KoalaBear)
impl Deserialize for Mersenne31 {
    fn deserialize_from(buf: &[u8]) -> VerificationResult<Self> {
        if buf.len() < 4 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 4];
        repr.copy_from_slice(&buf[..4]);
        let value = u32::from_le_bytes(repr);

        // Check that the value is in the valid range
        if value > KOALABEAR_MODULUS {
            return Err(VerificationError);
        }

        // For Mersenne31, the value 2^31 - 1 is mapped to 0
        let canonical_value = if value == KOALABEAR_MODULUS { 0 } else { value };

        Ok(Mersenne31::from_canonical_u32(canonical_value))
    }
}

// Implement Encoding for Mersenne31 (KoalaBear)
impl Encoding<[u8]> for Mersenne31 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_canonical_u32().to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use p3_field::Field;

    use super::*;

    #[test]
    fn test_koalabear_serialize_deserialize() {
        // Create a field element
        let element = Mersenne31::from_canonical_u32(54321);

        let mut buf = Vec::new();
        element.serialize_into(&mut buf);

        let deserialized = Mersenne31::deserialize_from(&buf).unwrap();
        assert_eq!(element, deserialized);
    }

    #[test]
    fn test_koalabear_encoding() {
        let element = Mersenne31::from_canonical_u32(98765);

        let encoded = element.encode();
        let encoded_bytes = encoded.as_ref();

        let deserialized = Mersenne31::deserialize_from(encoded_bytes).unwrap();
        assert_eq!(element, deserialized);
    }

    #[test]
    fn test_koalabear_decoding() {
        let buf = KoalaBearBuffer::default();
        let decoded = Mersenne31::decode(buf);
        assert_eq!(decoded, Mersenne31::ZERO);
    }

    #[test]
    fn test_koalabear_out_of_range() {
        // Try to deserialize a value larger than the modulus
        let buf = (KOALABEAR_MODULUS + 1).to_le_bytes();
        let result = Mersenne31::deserialize_from(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_koalabear_modulus_value() {
        // Test that the modulus value (2^31 - 1) is handled correctly
        let buf = KOALABEAR_MODULUS.to_le_bytes();
        let result = Mersenne31::deserialize_from(&buf).unwrap();
        assert_eq!(result, Mersenne31::ZERO);
    }
}
