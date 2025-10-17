//! SHAKE128 duplex sponge implementation.
//!
//! This module provides a duplex sponge interface implementation using SHAKE128,
//! which is a XOF (extendable output function) based on Keccak.

use digest::{ExtendableOutput, XofReader};
use zeroize::{DefaultIsZeroes, Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::DuplexSpongeInterface;

/// SHAKE128-based duplex sponge implementation.
///
/// This implementation uses SHAKE128 as the underlying XOF (extendable output function)
/// to provide absorb and squeeze operations compatible with the duplex sponge interface.
#[derive(Clone)]
pub struct XOF<H: ExtendableOutput> {
    /// The current SHAKE128 hasher state
    hasher: H,
    /// XOF reader for squeeze operations (None = absorbing, Some = squeezing)
    xof_reader: Option<H::Reader>,
}

impl<H> DuplexSpongeInterface for XOF<H>
where
    H: ExtendableOutput + Default + Zeroize,
    H::Reader: Clone,
{
    type U = u8;

    fn new() -> Self {
        Self::default()
    }

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        self.xof_reader = None;
        self.hasher.update(input);
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        self.xof_reader
            .get_or_insert(self.hasher.finalize_xof())
            .read(output);

        self
    }
}

impl<H: ExtendableOutput + Zeroize + DefaultIsZeroes> Zeroize for XOF<H> {
    fn zeroize(&mut self) {
        self.hasher.zeroize();
        self.xof_reader = None;
    }
}
impl<H: ExtendableOutput + Zeroize + DefaultIsZeroes> ZeroizeOnDrop for XOF<H> {}

impl<H: ExtendableOutput + Zeroize + DefaultIsZeroes> Default for XOF<H> {
    fn default() -> Self {
        Self {
            hasher: H::default(),
            xof_reader: None,
        }
    }
}
