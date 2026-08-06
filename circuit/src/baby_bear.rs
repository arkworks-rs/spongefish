//! [`spongefish::Unit`] support for `p3_baby_bear::BabyBear`.
//!
//! A direct `impl Unit for BabyBear` would violate the orphan rule, so the
//! field is carried through the transparent [`BabyBearUnit`] wrapper.

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use spongefish::Unit;

/// Transparent [`Unit`] wrapper around [`BabyBear`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BabyBearUnit(pub BabyBear);

impl Unit for BabyBearUnit {
    const ZERO: Self = Self(BabyBear::ZERO);
}

impl From<BabyBear> for BabyBearUnit {
    fn from(value: BabyBear) -> Self {
        Self(value)
    }
}

impl From<BabyBearUnit> for BabyBear {
    fn from(value: BabyBearUnit) -> Self {
        value.0
    }
}

impl core::ops::Deref for BabyBearUnit {
    type Target = BabyBear;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
