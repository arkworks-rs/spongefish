//! `ark_ff` bindings for sponge-specific unit support.

use ark_ff::{Fp, FpConfig, SmallFp, SmallFpConfig};

// Make arkworks field elements a valid Unit type
impl<C: FpConfig<N>, const N: usize> crate::Unit for Fp<C, N> {
    const ZERO: Self = C::ZERO;
}

// Make SmallFp field elements a valid Unit type
impl<P: SmallFpConfig> crate::Unit for SmallFp<P> {
    const ZERO: Self = P::ZERO;
}
