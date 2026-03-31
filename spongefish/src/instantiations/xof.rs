//! Generic XOF-based duplex sponge implementation.
//!
//! This module provides a duplex sponge interface implementation for any
//! XOF (extendable output function) that implements [`XofBackend`].

use digest::{ExtendableOutput, Update, XofReader};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::DuplexSpongeInterface;

/// Backend adapter used by [`XOF`].
///
/// This keeps the generic sponge wrapper usable across crates that expose XOFs
/// either through `digest` traits or through inherent methods such as BLAKE3.
pub trait XofBackend: Sized {
    /// Reader returned by the backend when squeezing.
    type Reader: Clone;

    /// Absorb more input into the backend state.
    fn update(&mut self, input: &[u8]);

    /// Finalize the backend into a squeeze reader.
    fn finalize_xof(self) -> Self::Reader;

    /// Read more bytes from the squeeze reader.
    fn read(reader: &mut Self::Reader, output: &mut [u8]);
}

#[cfg(feature = "sha3")]
impl XofBackend for sha3::Shake128 {
    type Reader = <Self as ExtendableOutput>::Reader;

    fn update(&mut self, input: &[u8]) {
        Update::update(self, input);
    }

    fn finalize_xof(self) -> Self::Reader {
        ExtendableOutput::finalize_xof(self)
    }

    fn read(reader: &mut Self::Reader, output: &mut [u8]) {
        XofReader::read(reader, output);
    }
}

#[cfg(feature = "k12")]
impl XofBackend for k12::KangarooTwelve<'static> {
    type Reader = <Self as ExtendableOutput>::Reader;

    fn update(&mut self, input: &[u8]) {
        Update::update(self, input);
    }

    fn finalize_xof(self) -> Self::Reader {
        ExtendableOutput::finalize_xof(self)
    }

    fn read(reader: &mut Self::Reader, output: &mut [u8]) {
        XofReader::read(reader, output);
    }
}

#[cfg(feature = "blake3")]
impl XofBackend for blake3::Hasher {
    type Reader = blake3::OutputReader;

    fn update(&mut self, input: &[u8]) {
        self.update(input);
    }

    #[allow(clippy::use_self)]
    fn finalize_xof(self) -> Self::Reader {
        blake3::Hasher::finalize_xof(&self)
    }

    fn read(reader: &mut Self::Reader, output: &mut [u8]) {
        reader.fill(output);
    }
}

/// Generic XOF-based duplex sponge implementation.
///
/// This implementation uses any XOF (extendable output function) that implements
/// [`XofBackend`] to provide absorb and squeeze operations compatible with the
/// duplex sponge interface. Examples include SHAKE128, SHAKE256, TurboShake,
/// and BLAKE3.
#[derive(Clone)]
pub struct XOF<H: XofBackend> {
    /// The current XOF hasher state
    hasher: H,
    /// XOF reader for squeeze operations (None = absorbing, Some = squeezing)
    xof_reader: Option<H::Reader>,
}

impl<H> DuplexSpongeInterface for XOF<H>
where
    H: XofBackend + Clone + Default,
{
    type U = u8;

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        self.xof_reader = None;
        self.hasher.update(input);
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        let reader = self
            .xof_reader
            .get_or_insert_with(|| self.hasher.clone().finalize_xof());
        H::read(reader, output);

        self
    }

    fn ratchet(&mut self) -> &mut Self {
        todo!()
    }
}

#[cfg(feature = "zeroize")]
impl<H> Zeroize for XOF<H>
where
    H: XofBackend + Zeroize,
{
    fn zeroize(&mut self) {
        self.hasher.zeroize();
        self.xof_reader = None;
    }
}

#[cfg(feature = "zeroize")]
impl<H> ZeroizeOnDrop for XOF<H> where H: XofBackend + Zeroize {}

impl<H: XofBackend + Default> Default for XOF<H> {
    fn default() -> Self {
        Self {
            hasher: H::default(),
            xof_reader: None,
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
        }
    }
}
