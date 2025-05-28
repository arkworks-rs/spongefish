//! **Warning**: this function is not SHA3.
//! Despite internally we use the same permutation function,
//! we build a duplex sponge in overwrite mode
//! on the top of it using the `DuplexSponge` trait.
use std::fmt::Debug;

use zerocopy::{transmute_mut, FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::{DuplexSponge, Permutation};

/// A duplex sponge based on the permutation [`keccak::f1600`]
/// using [`DuplexSponge`].
pub type Keccak = DuplexSponge<AlignedKeccakF1600>;

/// This is a wrapper around 200-byte buffer that's always 8-byte aligned
/// to make pointers to it safely convertible to pointers to [u64; 25]
/// (since u64 words must be 8-byte aligned)
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Zeroize,
    ZeroizeOnDrop,
    Immutable,
    KnownLayout,
    FromBytes,
    IntoBytes,
)]
#[repr(align(8))]
pub struct AlignedKeccakF1600([u8; 200]);

/// Censored version of Debug
impl Debug for AlignedKeccakF1600 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AlignedKeccakF1600")
            .field(&"<redacted>")
            .finish()
    }
}

impl Permutation for AlignedKeccakF1600 {
    type U = u8;
    const N: usize = 136 + 64;
    const R: usize = 136;

    fn new(tag: [u8; 32]) -> Self {
        let mut state = Self::default();
        state.0[Self::R..Self::R + 32].copy_from_slice(&tag);
        state
    }

    fn permute(&mut self) {
        keccak::f1600(transmute_mut!(self));
    }
}

impl Default for AlignedKeccakF1600 {
    fn default() -> Self {
        Self([0u8; Self::N])
    }
}

impl AsRef<[u8]> for AlignedKeccakF1600 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for AlignedKeccakF1600 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
