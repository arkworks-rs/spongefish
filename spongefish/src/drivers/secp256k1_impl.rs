//! secp256k1 bindings for sponge-specific unit support.

use k256::{elliptic_curve::ff::Field, Scalar};

impl crate::Unit for Scalar {
    const ZERO: Self = <Self as Field>::ZERO;
}
