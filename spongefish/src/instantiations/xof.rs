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
        if input.is_empty() {
            return self;
        }

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

#[cfg(all(test, feature = "sha3"))]
mod tests {
    use super::XOF;
    use crate::duplex_sponge::DuplexSpongeInterface;

    #[test]
    fn empty_absorb_is_noop_while_squeezing() {
        let mut control = XOF::<sha3::Shake128>::default();
        control.absorb(b"abc");
        let mut expected_prefix = [0u8; 5];
        control.squeeze(&mut expected_prefix);
        let mut expected_suffix = [0u8; 64];
        control.squeeze(&mut expected_suffix);

        let mut with_empty_absorb = XOF::<sha3::Shake128>::default();
        with_empty_absorb.absorb(b"abc");
        let mut actual_prefix = [0u8; 5];
        with_empty_absorb.squeeze(&mut actual_prefix);
        with_empty_absorb.absorb(&[]);
        let mut actual_suffix = [0u8; 64];
        with_empty_absorb.squeeze(&mut actual_suffix);

        assert_eq!(actual_prefix, expected_prefix);
        assert_eq!(actual_suffix, expected_suffix);
    }
}
