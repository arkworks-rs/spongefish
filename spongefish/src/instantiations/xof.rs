//! Generic XOF-based duplex sponge implementation.
//!
//! This module provides a duplex sponge interface implementation for any
//! XOF (extendable output function) that implements the [`ExtendableOutput`] trait.

use digest::{ExtendableOutput, XofReader};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::DuplexSpongeInterface;

/// Generic XOF-based duplex sponge implementation.
///
/// This implementation uses any XOF (extendable output function) that implements
/// [`ExtendableOutput`] to provide absorb and squeeze operations compatible with
/// the duplex sponge interface. Examples include SHAKE128, SHAKE256, and TurboShake.
#[derive(Clone)]
pub struct XOF<H: ExtendableOutput> {
    /// The current XOF hasher state
    hasher: H,
    /// XOF reader for squeeze operations (None = absorbing, Some = squeezing)
    xof_reader: Option<H::Reader>,
}

impl<H> DuplexSpongeInterface for XOF<H>
where
    H: ExtendableOutput + Clone + Default,
    H::Reader: Clone,
{
    type U = u8;

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        self.xof_reader = None;
        self.hasher.update(input);
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        self.xof_reader
            .get_or_insert_with(|| self.hasher.clone().finalize_xof())
            .read(output);

        self
    }

    fn ratchet(&mut self) -> &mut Self {
        todo!()
    }
}

#[cfg(feature = "zeroize")]
impl<H> Zeroize for XOF<H>
where
    H: ExtendableOutput + Default + Zeroize,
{
    fn zeroize(&mut self) {
        self.hasher.zeroize();
        self.xof_reader = None;
    }
}

#[cfg(feature = "zeroize")]
impl<H> ZeroizeOnDrop for XOF<H> where H: ExtendableOutput + Default {}

impl<H: ExtendableOutput + Default> Default for XOF<H> {
    fn default() -> Self {
        Self {
            hasher: H::default(),
            xof_reader: None,
        }
    }
}

#[cfg(feature = "sha3")]
impl XOF<sha3::Shake128> {
    /// Build a SHAKE128 sponge using the RFC test-vector IV convention.
    #[must_use]
    pub fn from_iv(iv: [u8; 64]) -> Self {
        use digest::Update;

        const RATE: usize = 168;

        let mut hasher = sha3::Shake128::default();
        let mut initial_block = [0u8; RATE];
        initial_block[..iv.len()].copy_from_slice(&iv);
        hasher.update(&initial_block);

        Self {
            hasher,
            xof_reader: None,
        }
    }
}
