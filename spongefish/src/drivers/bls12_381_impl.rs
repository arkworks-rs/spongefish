//! BLS12-381 bindings for sponge-specific unit support.

use bls12_381::Scalar;

impl crate::Unit for Scalar {
    const ZERO: Self = Self::zero();
}
