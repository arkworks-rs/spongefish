use core::fmt::Debug;

use zerocopy::IntoBytes;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::Permutation;

/// Keccak permutation internal state: 25 64-bit words,
/// or equivalently 200 bytes in little-endian order.
#[derive(Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct KeccakF1600([u64; 25]);

impl Permutation for KeccakF1600 {
    type U = u8;
    const N: usize = 136 + 64;
    const R: usize = 136;

    fn new() -> Self {
        Self::default()
    }

    fn permute(&mut self) {
        keccak::f1600(&mut self.0);
    }
}

impl AsRef<[u8]> for KeccakF1600 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsMut<[u8]> for KeccakF1600 {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_bytes()
    }
}

/// Censored version of Debug
impl Debug for KeccakF1600 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AlignedKeccakF1600")
            .field(&"<redacted>")
            .finish()
    }
}
