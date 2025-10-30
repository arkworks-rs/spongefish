//! XXX. we do two things: define hash, and instantiate the duplexspongeinterface
//!
//! This code is inspired from libsignal's poksho:
//! <https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shosha256.rs>.
//! With the following generalizations:
//! - squeeze satisfies streaming
//!     ```text
//!     squeeze(1); squeeze(1); squeeze(1) = squeeze(3);
//!     ```
//! - the implementation is for any Digest.

use alloc::vec::Vec;

use digest::{
    core_api::{Block, BlockSizeUser},
    typenum::Unsigned,
    Digest, FixedOutputReset, Output, Reset,
};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::DuplexSpongeInterface;

/// A Bridge to our sponge interface for legacy `Digest` implementations.
#[derive(Clone)]
pub struct Hash<D: Digest + Clone + Reset + BlockSizeUser> {
    /// The underlying hasher.
    hasher: D,
    /// Cached digest
    cv: Output<D>,
    /// Current operation, keeping state between absorb and squeeze
    /// across multiple calls when streaming.
    mode: Mode,
    /// Digest bytes left over from a previous squeeze.
    leftovers: Vec<u8>,
}

impl<D: BlockSizeUser + Digest + Clone + FixedOutputReset> DuplexSpongeInterface for Hash<D> {
    type U = u8;

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        self.squeeze_end();

        if self.mode == Mode::Start {
            self.mode = Mode::Absorb;
            Digest::update(&mut self.hasher, Self::mask_absorb());
            Digest::update(&mut self.hasher, &self.cv);
        }

        Digest::update(&mut self.hasher, input);
        self
    }

    fn ratchet(&mut self) -> &mut Self {
        self.squeeze_end();
        // Double hash
        self.cv = <D as Digest>::digest(self.hasher.finalize_reset());
        // Restart the rest of the data
        #[cfg(feature = "zeroize")]
        self.leftovers.zeroize();
        self.leftovers.clear();
        self.mode = Mode::Start;
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        if self.mode == Mode::Start {
            self.mode = Mode::Squeeze(0);
            // create the prefix hash
            Digest::update(&mut self.hasher, Self::mask_squeeze());
            Digest::update(&mut self.hasher, &self.cv);
            self.squeeze(output)
        // If Absorbing, ratchet
        } else if self.mode == Mode::Absorb {
            self.ratchet();
            self.squeeze(output)
        // If we have no more data to squeeze, return
        } else if output.is_empty() {
            self
        // If we still have some digest not yet squeezed
        // from previous invocations, write it to the output.
        } else if !self.leftovers.is_empty() {
            let len = usize::min(output.len(), self.leftovers.len());
            output[..len].copy_from_slice(&self.leftovers[..len]);
            self.leftovers.drain(..len);
            self.squeeze(&mut output[len..])
        // Squeeze another digest
        } else if let Mode::Squeeze(i) = self.mode {
            // Add the squeeze mask, current digest, and index
            let mut output_hasher_prefix = self.hasher.clone();
            Digest::update(&mut output_hasher_prefix, i.to_be_bytes());
            let digest = output_hasher_prefix.finalize();
            // Copy the digest into the output, and store the rest for later
            let chunk_len = usize::min(output.len(), Self::DIGEST_SIZE);
            output[..chunk_len].copy_from_slice(&digest[..chunk_len]);
            self.leftovers.extend_from_slice(&digest[chunk_len..]);
            // Update the state
            self.mode = Mode::Squeeze(i + 1);
            self.squeeze(&mut output[chunk_len..])
        } else {
            unreachable!()
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Mode {
    Start,
    Absorb,
    Squeeze(usize),
}

impl<D: BlockSizeUser + Digest + Clone + Reset> Hash<D> {
    const BLOCK_SIZE: usize = D::BlockSize::USIZE;
    const DIGEST_SIZE: usize = D::OutputSize::USIZE;

    /// Create a block
    /// | start | 0000 0000 | end |
    fn pad_block(start: &[u8], end: &[u8]) -> Block<D> {
        debug_assert!(start.len() + end.len() < Self::BLOCK_SIZE);
        let mut mask = Block::<D>::default();
        mask[..start.len()].copy_from_slice(start);
        mask[Self::BLOCK_SIZE - end.len()..].copy_from_slice(end);
        mask
    }

    fn mask_absorb() -> Block<D> {
        Self::pad_block(&[], &[0x00])
    }

    fn mask_squeeze() -> Block<D> {
        Self::pad_block(&[], &[0x01])
    }

    fn mask_squeeze_end() -> Block<D> {
        Self::pad_block(&[], &[0x02])
    }

    fn squeeze_end(&mut self) {
        if let Mode::Squeeze(count) = self.mode {
            Digest::reset(&mut self.hasher);

            // append to the state the squeeze mask
            // with the length of the data read so far
            // and the current digest
            let byte_count = count * Self::DIGEST_SIZE - self.leftovers.len();
            let mut squeeze_hasher = D::new();
            Digest::update(&mut squeeze_hasher, Self::mask_squeeze_end());
            Digest::update(&mut squeeze_hasher, &self.cv);
            Digest::update(&mut squeeze_hasher, byte_count.to_be_bytes());
            self.cv = Digest::finalize(squeeze_hasher);

            // set the sponge state in absorb mode
            self.mode = Mode::Start;
            self.leftovers.clear();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<D: Clone + Digest + Reset + BlockSizeUser> Zeroize for Hash<D> {
    fn zeroize(&mut self) {
        self.cv.zeroize();
        Digest::reset(&mut self.hasher);
    }
}

#[cfg(feature = "zeroize")]
impl<D: Clone + Digest + Reset + BlockSizeUser> Drop for Hash<D> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<D: BlockSizeUser + Digest + Clone + FixedOutputReset> Default for Hash<D> {
    fn default() -> Self {
        Self {
            hasher: D::new(),
            cv: Output::<D>::default(),
            mode: Mode::Start,
            leftovers: Vec::new(),
        }
    }
}

#[cfg(all(test, feature = "sha2"))]
#[test]
fn test_shosha() {
    let expected = b"\xEB\xE4\xEF\x29\xE1\x8A\xA5\x41\x37\xED\xD8\x9C\x23\xF8\
    \xBF\xEA\xC2\x73\x1C\x9F\x67\x5D\xA2\x0E\x7C\x67\xD5\xAD\
    \x68\xD7\xEE\x2D\x40\xA4\x52\x32\xB5\x99\x55\x2D\x46\xB5\
    \x20\x08\x2F\xB2\x70\x59\x71\xF0\x7B\x31\x58\xB0\x72\xB6\
    \x3A\xB0\x93\x4A\x05\xE6\xAF\x64";
    let mut sho = Hash::<sha2::Sha256>::default();
    let mut got = [0u8; 64];
    sho.absorb(b"asd");
    sho.ratchet();
    // streaming absorb
    sho.absorb(b"asd");
    sho.absorb(b"asd");
    // streaming squeeze
    sho.squeeze(&mut got[..32]);
    sho.squeeze(&mut got[32..]);
    assert_eq!(&got, expected);

    let expected = b"\xEB\xE4\xEF\x29\xE1\x8A\xA5\x41\x37\xED\xD8\x9C\x23\xF8\
    \xBF\xEA\xC2\x73\x1C\x9F\x67\x5D\xA2\x0E\x7C\x67\xD5\xAD\
    \x68\xD7\xEE\x2D\x40\xA4\x52\x32\xB5\x99\x55\x2D\x46\xB5\
    \x20\x08\x2F\xB2\x70\x59\x71\xF0\x7B\x31\x58\xB0\x72\xB6\
    \x3A\xB0\x93\x4A\x05\xE6\xAF\x64\x48";
    let mut sho = Hash::<sha2::Sha256>::default();
    let mut got = [0u8; 65];
    sho.absorb(b"asd");
    sho.ratchet();
    sho.absorb(b"asdasd");
    sho.squeeze(&mut got);
    assert_eq!(&got, expected);

    let expected = b"\x0D\xDE\xEA\x97\x3F\x32\x10\xF7\x72\x5A\x3C\xDB\x24\x73\
    \xF8\x73\xAE\xAB\x8F\xEB\x32\xB8\x0D\xEE\x67\xF0\xCD\xE7\
    \x95\x4E\x92\x9A\x4E\x78\x7A\xEF\xEE\x6D\xBE\x91\xD3\xFF\
    \xF1\x62\x1A\xAB\x8D\x0D\x29\x19\x4F\x8A\xF9\x86\xD6\xF3\
    \x57\xAD\xD0\x15\x0D\xF7\xD9";

    let mut sho = Hash::<sha2::Sha256>::default();
    let mut got = [0u8; 150];
    sho.absorb(b"");
    sho.ratchet();
    sho.absorb(b"abc");
    sho.ratchet();
    sho.absorb(&[0u8; 63]);
    sho.ratchet();
    sho.absorb(&[0u8; 64]);
    sho.ratchet();
    sho.absorb(&[0u8; 65]);
    sho.ratchet();
    sho.absorb(&[0u8; 127]);
    sho.ratchet();
    sho.absorb(&[0u8; 128]);
    sho.ratchet();
    sho.absorb(&[0u8; 129]);
    sho.ratchet();
    sho.squeeze(&mut got[..63]);
    // assert_eq!(&got[..63], &hex::decode("5bddc29ac27fd88bf682b07dd5c496b065f6ce11fd7aa77d1e13c609d77b9b2fed21b470f71a7f1fdfbfa895060c51302e782f440305d12ec85a492635dd3a").unwrap()[..]);
    sho.squeeze_end();
    sho.squeeze(&mut got[..64]);
    // assert_eq!(&got[..64], &hex::decode("0ad17fc123d823548447b16ebebc8c21243dc4c59dd95525b7321c3b92a58e30156ec8c8e70987ed1483d2be84e89d2be5813fb1b8ab82119608120a2694a425").unwrap()[..]);
    sho.squeeze_end();
    sho.squeeze(&mut got[..65]);
    sho.squeeze_end();
    sho.squeeze(&mut got[..127]);
    sho.squeeze_end();
    sho.squeeze(&mut got[..128]);
    sho.squeeze_end();
    sho.squeeze(&mut got[..129]);
    assert_eq!(got[0], 0xd0);
    sho.absorb(b"def");
    sho.ratchet();
    sho.squeeze(&mut got[..63]);
    assert_eq!(&got[..63], expected);
}
