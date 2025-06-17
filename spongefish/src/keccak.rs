//! **Warning**: this function is not SHA3.
//! Despite internally we use the same permutation function,
//! we build a duplex sponge in overwrite mode
//! on the top of it using the `DuplexSponge` trait.
use std::fmt::Debug;

use zerocopy::IntoBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::{DuplexSponge, Permutation};

/// A duplex sponge based on the permutation [`keccak::f1600`]
/// using [`DuplexSponge`].
///
/// **Warning**: This function is not SHA3.
/// Despite internally we use the same permutation function,
/// we build a duplex sponge in overwrite mode
/// on the top of it using the `DuplexSponge` trait.
pub type Keccak = DuplexSponge<KeccakF1600>;

/// Keccak permutation internal state: 25 64-bit words,
/// or equivalently 200 bytes in little-endian order.
#[derive(Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct KeccakF1600([u64; 25]);

impl Permutation for KeccakF1600 {
    type U = u8;
    const N: usize = 136 + 64;
    const R: usize = 136;

    fn new(iv: [u8; 32]) -> Self {
        let mut state = Self::default();
        state.as_mut()[Self::R..Self::R + 32].copy_from_slice(&iv);
        state
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AlignedKeccakF1600")
            .field(&"<redacted>")
            .finish()
    }
}
