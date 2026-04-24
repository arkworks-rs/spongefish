//! Plonky3's KoalaBear field codec implementation
use p3_koala_bear::KoalaBear;

const KOALABEAR_ZERO: KoalaBear = unsafe { core::mem::transmute(0u32) };

// Make KoalaBear a valid Unit type
impl crate::Unit for KoalaBear {
    const ZERO: Self = KOALABEAR_ZERO;
}
// Encoding/decoding for Plonky3 types lives in `ia-core` (Argus-owned traits).
