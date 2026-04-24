//! curve25519-dalek bindings for sponge-specific unit support.

use curve25519_dalek::scalar::Scalar;

impl crate::Unit for Scalar {
    const ZERO: Self = Self::ZERO;
}
