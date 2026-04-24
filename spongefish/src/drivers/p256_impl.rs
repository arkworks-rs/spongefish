//! p256 bindings for sponge-specific unit support.

use p256::Scalar;

impl crate::Unit for Scalar {
    const ZERO: Self = Self::ZERO;
}
