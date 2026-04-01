//! Generic XOF-based duplex sponge implementation.
//!
//! This module provides a duplex sponge interface implementation for any
//! XOF (extendable output function) that implements [`digest::ExtendableOutput`].

use digest::{ExtendableOutput, Update, XofReader};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::DuplexSpongeInterface;

/// Generic XOF-based duplex sponge implementation.
///
/// This implementation uses any XOF (extendable output function) that implements
/// [`digest::ExtendableOutput`] to provide absorb and squeeze operations
/// compatible with the duplex sponge interface. Examples include SHAKE128,
/// SHAKE256, TurboSHAKE, KangarooTwelve, and BLAKE3.
pub struct XOF<H: ExtendableOutput> {
    /// The current XOF hasher state
    hasher: H,
    /// XOF reader for squeeze operations (None = absorbing, Some = squeezing)
    xof_reader: Option<H::Reader>,
    /// Number of bytes already squeezed from the current reader.
    ///
    /// This is needed to preserve `Clone` semantics for XOFs whose reader type
    /// cannot itself be cloned.
    squeezed: usize,
}

impl<H> XOF<H>
where
    H: ExtendableOutput + Clone,
{
    /// Rebuild the reader at its current offset from the cloneable hasher state.
    fn rebuild_reader(&self) -> H::Reader {
        let mut reader = ExtendableOutput::finalize_xof(self.hasher.clone());
        let mut skipped = self.squeezed;
        let mut scratch = [0u8; 256];

        while skipped != 0 {
            let chunk_len = usize::min(skipped, scratch.len());
            XofReader::read(&mut reader, &mut scratch[..chunk_len]);
            skipped -= chunk_len;
        }

        reader
    }
}

impl<H> Clone for XOF<H>
where
    H: ExtendableOutput + Clone,
{
    fn clone(&self) -> Self {
        let xof_reader = self.xof_reader.as_ref().map(|_| self.rebuild_reader());

        Self {
            hasher: self.hasher.clone(),
            xof_reader,
            squeezed: self.squeezed,
        }
    }
}

impl<H> DuplexSpongeInterface for XOF<H>
where
    H: ExtendableOutput + Clone + Default,
{
    type U = u8;

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        self.xof_reader = None;
        self.squeezed = 0;
        Update::update(&mut self.hasher, input);
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        let reader = self
            .xof_reader
            .get_or_insert_with(|| ExtendableOutput::finalize_xof(self.hasher.clone()));
        XofReader::read(reader, output);
        self.squeezed += output.len();

        self
    }

    fn ratchet(&mut self) -> &mut Self {
        todo!()
    }
}

#[cfg(feature = "zeroize")]
impl<H> Zeroize for XOF<H>
where
    H: ExtendableOutput + Zeroize,
{
    fn zeroize(&mut self) {
        self.hasher.zeroize();
        self.xof_reader = None;
        self.squeezed = 0;
    }
}

#[cfg(feature = "zeroize")]
impl<H> ZeroizeOnDrop for XOF<H> where H: ExtendableOutput + Zeroize {}

impl<H> Default for XOF<H>
where
    H: ExtendableOutput + Default,
{
    fn default() -> Self {
        Self {
            hasher: H::default(),
            xof_reader: None,
            squeezed: 0,
        }
    }
}

#[cfg(feature = "sha3")]
impl XOF<sha3::Shake128> {
    pub(crate) fn from_protocol_id(protocol_id: [u8; 64]) -> Self {
        const RATE: usize = 168;

        let mut hasher = sha3::Shake128::default();
        let mut initial_block = [0u8; RATE];
        initial_block[..protocol_id.len()].copy_from_slice(&protocol_id);
        digest::Update::update(&mut hasher, &initial_block);

        Self {
            hasher,
            xof_reader: None,
            squeezed: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::XOF;
    use crate::duplex_sponge::DuplexSpongeInterface;

    fn assert_clone_preserves_squeeze_position<H>()
    where
        H: digest::ExtendableOutput + Clone + Default,
    {
        let mut sponge = XOF::<H>::default();
        sponge.absorb(b"spongefish clone test");

        let mut prefix = [0u8; 13];
        sponge.squeeze(&mut prefix);

        let mut cloned = sponge.clone();
        let mut original_tail = [0u8; 64];
        let mut cloned_tail = [0u8; 64];

        sponge.squeeze(&mut original_tail);
        cloned.squeeze(&mut cloned_tail);

        assert_eq!(original_tail, cloned_tail);
    }

    #[cfg(feature = "sha3")]
    #[test]
    fn shake128_clone_preserves_squeeze_position() {
        assert_clone_preserves_squeeze_position::<sha3::Shake128>();
    }

    #[cfg(feature = "k12")]
    #[test]
    fn kangaroo_twelve_clone_preserves_squeeze_position() {
        assert_clone_preserves_squeeze_position::<k12::Kt128<'static>>();
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn blake3_clone_preserves_squeeze_position() {
        assert_clone_preserves_squeeze_position::<blake3::Hasher>();
    }
}
