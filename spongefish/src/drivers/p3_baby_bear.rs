//! Plonky3's BabyBear field codec implementation
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;

use crate::{
    codecs::{Decoding, Encoding},
    io::NargDeserialize,
    VerificationError, VerificationResult,
};

// xxx. implement Permutation for CryptographicPermutation.

const BABYBEAR_ZERO: BabyBear = unsafe { core::mem::transmute(0u32) };

// Make BabyBear a valid Unit type
impl crate::Unit for BabyBear {
    const ZERO: Self = BABYBEAR_ZERO;
}

// Implement Decoding for BabyBear
//
// Sampling 32 bits and reducing them modulo BABYBEAR::ORDER_U32
// would give us 31.2064 bits of indistinguishability, which feels weak.
// Sampling 33 bits and reducing them modulo BABYBEAR::ORDER_U32
// would give us 32.4474 bits of indistinguishability, which is sufficient but weird to use
// via built-in integer types.
//
// We are opting for sampling a u64 and then reducing it modulo BABYBEAR::ORDER_U32
// which gives us 64.2592 bits of indistinguishability.
//
// The above numbers were obtained in Python via:
// ```
// f = lambda a, b: math.log2(2. * (a - (b % a)) / a / b)
// f(2013265921, 1<<32), f(2013265921, 1<<33), f(2013265921, 1<<64)
// ```
impl Decoding<[u8]> for BabyBear {
    type Repr = [u8; 8];

    fn decode(buf: Self::Repr) -> Self {
        let n = u64::from_le_bytes(buf);
        Self::new((n % u64::from(Self::ORDER_U32)) as u32)
    }
}

// Implement Deserialize for BabyBear
impl NargDeserialize for BabyBear {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 4 {
            return Err(VerificationError);
        }
        let mut repr = [0u8; 4];
        repr.copy_from_slice(&buf[..4]);
        let value = u32::from_le_bytes(repr);

        // Check that the value is in the valid range
        if value >= Self::ORDER_U32 {
            return Err(VerificationError);
        }

        Ok(Self::new(value))
    }
}

// Implement Encoding for BabyBear
impl Encoding<[u8]> for BabyBear {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_canonical_u32().to_le_bytes()
    }
}
