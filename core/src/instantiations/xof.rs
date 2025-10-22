//! Generic XOF-based duplex sponge implementation.
//!
//! This module provides a duplex sponge interface implementation for any
//! XOF (extendable output function) that implements the [`ExtendableOutput`] trait.

use digest::{ExtendableOutput, Reset, XofReader};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::DuplexSpongeInterface;

/// Generic XOF-based duplex sponge implementation.
///
/// This implementation uses any XOF (extendable output function) that implements
/// [`ExtendableOutput`] to provide absorb and squeeze operations compatible with
/// the duplex sponge interface. Examples include SHAKE128, SHAKE256, and TurboShake.
#[derive(Clone)]
pub struct XOF<H: Default + ExtendableOutput> {
    /// The current XOF hasher state
    hasher: H,
    /// XOF reader for squeeze operations (None = absorbing, Some = squeezing)
    xof_reader: Option<H::Reader>,
}

impl<H> DuplexSpongeInterface for XOF<H>
where
    H: ExtendableOutput + Clone + Default + Reset,
    H::Reader: Clone,
{
    type U = u8;

    fn new() -> Self {
        Self {
            hasher: H::default(),
            xof_reader: None,
        }
    }

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        self.xof_reader = None;
        self.hasher.update(input);
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        self.xof_reader
            .get_or_insert(self.hasher.clone().finalize_xof())
            .read(output);

        self
    }
}

impl<H> Zeroize for XOF<H>
where
    H: ExtendableOutput + Default + Reset,
{
    fn zeroize(&mut self) {
        // Reset hasher to initial state using the Reset trait
        self.hasher.reset();
        // Clear the reader
        self.xof_reader = None;
    }
}

impl<H> ZeroizeOnDrop for XOF<H>
where
    H: ExtendableOutput + Default + Reset,
{
}

impl<H: ExtendableOutput + Default> Default for XOF<H> {
    fn default() -> Self {
        Self {
            hasher: H::default(),
            xof_reader: None,
        }
    }
}
