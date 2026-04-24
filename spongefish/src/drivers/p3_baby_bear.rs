//! Plonky3's BabyBear field codec implementation
use p3_baby_bear::BabyBear;

// xxx. implement Permutation for CryptographicPermutation.

const BABYBEAR_ZERO: BabyBear = unsafe { core::mem::transmute(0u32) };

// Make BabyBear a valid Unit type
impl crate::Unit for BabyBear {
    const ZERO: Self = BABYBEAR_ZERO;
}
// Encoding/decoding for Plonky3 types lives in `ia-core` (Argus-owned traits).
