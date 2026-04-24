//! Plonky3's Mersenne31 field codec implementation

use p3_mersenne_31::Mersenne31;

const MERSENNE31_ZERO: Mersenne31 = unsafe { core::mem::transmute(0u32) };

impl crate::Unit for Mersenne31 {
    const ZERO: Self = MERSENNE31_ZERO;
}
// Encoding/decoding for Plonky3 types lives in `ia-core` (Argus-owned traits).
