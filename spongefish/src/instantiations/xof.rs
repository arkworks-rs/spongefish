//! Generic XOF-based duplex sponge implementation.
//!
//! This module provides a duplex sponge interface implementation for any
//! XOF (extendable output function) that implements [`digest::ExtendableOutput`].

#[cfg(feature = "blake3")]
use blake3::OutputReader;
use digest::{ExtendableOutput, Update, XofReader};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::DuplexSpongeInterface;

/// Generic XOF-based duplex sponge implementation.
///
/// This implementation uses any XOF (extendable output function) that implements
/// [`digest::ExtendableOutput`] to provide absorb and squeeze operations
/// compatible with the duplex sponge interface. Examples include SHAKE128,
/// SHAKE256, TurboSHAKE, and KangarooTwelve.
#[derive(Clone)]
pub struct XOF<H: ExtendableOutput>
where
    H::Reader: Clone,
{
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
        Update::update(&mut self.hasher, input);
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        let reader = self
            .xof_reader
            .get_or_insert_with(|| ExtendableOutput::finalize_xof(self.hasher.clone()));
        XofReader::read(reader, output);

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
    H::Reader: Clone,
{
    fn zeroize(&mut self) {
        self.hasher.zeroize();
        self.xof_reader = None;
    }
}

#[cfg(feature = "zeroize")]
impl<H> ZeroizeOnDrop for XOF<H>
where
    H: ExtendableOutput + Zeroize,
    H::Reader: Clone,
{
}

impl<H> Default for XOF<H>
where
    H: ExtendableOutput + Default,
    H::Reader: Clone,
{
    fn default() -> Self {
        Self {
            hasher: H::default(),
            xof_reader: None,
        }
    }
}

/// BLAKE3 XOF used as a [`DuplexSpongeInterface`][`crate::DuplexSpongeInterface`].
///
/// BLAKE3's digest trait integration currently targets a newer `digest`
/// generation than the rest of this crate graph, so it keeps a concrete wrapper
/// over BLAKE3's inherent XOF API.
#[cfg(feature = "blake3")]
#[derive(Clone, Default)]
pub struct Blake3 {
    hasher: blake3::Hasher,
    xof_reader: Option<OutputReader>,
}

#[cfg(feature = "blake3")]
impl DuplexSpongeInterface for Blake3 {
    type U = u8;

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        self.xof_reader = None;
        self.hasher.update(input);
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        let reader = self
            .xof_reader
            .get_or_insert_with(|| self.hasher.finalize_xof());
        reader.fill(output);
        self
    }

    fn ratchet(&mut self) -> &mut Self {
        todo!()
    }
}

#[cfg(all(feature = "blake3", feature = "zeroize"))]
impl Zeroize for Blake3 {
    fn zeroize(&mut self) {
        self.hasher.zeroize();
        self.xof_reader = None;
    }
}

#[cfg(all(feature = "blake3", feature = "zeroize"))]
impl ZeroizeOnDrop for Blake3 {}

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
        }
    }
}
