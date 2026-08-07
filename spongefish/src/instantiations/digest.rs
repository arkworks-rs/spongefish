//! A [`DuplexSpongeInterface`] bridge for fixed-output [`digest::Digest`] hash functions.
//!
//! This code is inspired by libsignal's poksho:
//! <https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shosha256.rs>,
//! with the following generalizations:
//! - squeeze satisfies streaming
//!     ```text
//!     squeeze(1); squeeze(1); squeeze(1) = squeeze(3);
//!     ```
//! - the implementation is for any Digest.

use alloc::vec::Vec;

use digest::{
    block_api::{Block, BlockSizeUser},
    typenum::Unsigned,
    Digest, FixedOutputReset, Output, Reset,
};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::DuplexSpongeInterface;

/// Digest bytes produced by a squeeze but not yet handed to a caller.
///
/// A plain `Vec<u8>` drained from the front made a partial squeeze quadratic:
/// every `squeeze` of `k` bytes shifted the whole remainder down. This holds a
/// read cursor instead, so consuming is O(1).
///
/// # Invariant
///
/// `pos <= buf.len()`, and [`Leftovers::len`] means the number of *unconsumed*
/// bytes. That second point is load-bearing: `squeeze_end` computes the
/// transcript-affecting `byte_count = count * DIGEST_SIZE - leftovers.len()`,
/// so `len` keeping its original meaning is what lets that arithmetic — and
/// the output bytes — stay exactly as they were.
#[derive(Clone, Default)]
struct Leftovers {
    buf: Vec<u8>,
    /// Bytes of `buf` already handed out.
    pos: usize,
}

impl Leftovers {
    /// The number of bytes not yet consumed.
    #[inline]
    fn len(&self) -> usize {
        debug_assert!(self.pos <= self.buf.len(), "cursor past the buffer");
        self.buf.len() - self.pos
    }

    #[inline]
    const fn is_empty(&self) -> bool {
        // Compared directly rather than via `len() == 0`: this runs once per
        // digest in the squeeze loop.
        self.pos == self.buf.len()
    }

    /// The unconsumed bytes.
    #[inline]
    fn as_slice(&self) -> &[u8] {
        debug_assert!(self.pos <= self.buf.len(), "cursor past the buffer");
        &self.buf[self.pos..]
    }

    /// Marks the first `count` unconsumed bytes as consumed.
    #[inline]
    fn consume(&mut self, count: usize) {
        debug_assert!(count <= self.len(), "consuming more than is buffered");
        self.pos += count;
    }

    /// Replaces the unconsumed bytes' tail with `bytes`.
    ///
    /// The consumed prefix is dropped here rather than on every `consume`,
    /// which is what makes consuming O(1) while keeping the buffer bounded by
    /// one digest.
    #[inline]
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        // A squeeze that consumes whole digests leaves nothing over and buffers
        // nothing — every iteration of a contiguous multi-digest squeeze takes
        // this path, so keep it free of any buffer traffic.
        if bytes.is_empty() && self.buf.is_empty() {
            // `pos <= buf.len() == 0` forces `pos == 0`, so there is nothing
            // to reset and this path touches no memory at all.
            debug_assert_eq!(self.pos, 0, "cursor past the buffer");
            return;
        }
        if self.pos == self.buf.len() {
            self.buf.clear();
        } else if self.pos > 0 {
            self.buf.drain(..self.pos);
        }
        self.pos = 0;
        self.buf.extend_from_slice(bytes);
    }

    /// Drops every buffered byte, consumed or not.
    ///
    /// Resets the cursor as well as the buffer: a `pos` surviving a `clear`
    /// would make `len` — and therefore `squeeze_end`'s byte count — wrong.
    #[inline]
    fn clear(&mut self) {
        self.buf.clear();
        self.pos = 0;
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Leftovers {
    fn zeroize(&mut self) {
        // Wipes the consumed prefix too: those bytes were squeezed output and
        // are exactly as sensitive as the unconsumed ones.
        self.buf.zeroize();
        self.pos = 0;
    }
}

/// A bridge to our sponge interface for legacy `Digest` implementations.
#[derive(Clone)]
pub struct Hash<D: Digest + Clone + Reset + BlockSizeUser> {
    /// The underlying hasher.
    hasher: D,
    /// Cached digest.
    cv: Output<D>,
    /// Current operation, keeping state between absorb and squeeze
    /// across multiple calls when streaming.
    mode: Mode,
    /// Digest bytes left over from a previous squeeze.
    leftovers: Leftovers,
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

    fn squeeze(&mut self, mut output: &mut [u8]) -> &mut Self {
        // Enter squeezing mode. From `Absorb` we ratchet first, which lands
        // back in `Start`; from `Start` we install the squeeze prefix. Both
        // transitions happen even for an empty output.
        if self.mode == Mode::Absorb {
            self.ratchet();
        }
        if self.mode == Mode::Start {
            self.mode = Mode::Squeeze(0);
            // create the prefix hash
            Digest::update(&mut self.hasher, Self::mask_squeeze());
            Digest::update(&mut self.hasher, &self.cv);
        }

        // Iterative by construction: one digest block per iteration. A
        // recursive formulation costs one stack frame per `DIGEST_SIZE` bytes
        // and overflows the stack on large squeezes.
        while !output.is_empty() {
            // If we still have some digest not yet squeezed
            // from previous invocations, write it to the output.
            if !self.leftovers.is_empty() {
                let len = usize::min(output.len(), self.leftovers.len());
                output[..len].copy_from_slice(&self.leftovers.as_slice()[..len]);
                self.leftovers.consume(len);
                output = &mut output[len..];
                continue;
            }

            // Squeeze another digest: the squeeze mask, current digest, and index.
            // Encode the index as a fixed-width `u64` (not `usize`) so the absorbed
            // bytes are identical on 32- and 64-bit targets; otherwise a 64-bit
            // prover and a 32-bit verifier (e.g. wasm32) derive different outputs.
            let Mode::Squeeze(i) = self.mode else {
                unreachable!("squeezing mode is installed above")
            };
            let mut output_hasher_prefix = self.hasher.clone();
            Digest::update(&mut output_hasher_prefix, (i as u64).to_be_bytes());
            let digest = output_hasher_prefix.finalize();
            // Copy the digest into the output, and store the rest for later
            let chunk_len = usize::min(output.len(), Self::DIGEST_SIZE);
            output[..chunk_len].copy_from_slice(&digest[..chunk_len]);
            self.leftovers.extend_from_slice(&digest[chunk_len..]);
            // Update the state
            self.mode = Mode::Squeeze(i + 1);
            output = &mut output[chunk_len..];
        }
        self
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Mode {
    Start,
    Absorb,
    Squeeze(usize),
}

impl<D: BlockSizeUser + Digest + Clone + FixedOutputReset> Hash<D> {
    /// One-way state commitment (poksho-style double hash), used internally to
    /// transition from absorbing to squeezing. This is a design detail of this
    /// digest bridge, not part of the duplex sponge interface.
    pub fn ratchet(&mut self) -> &mut Self {
        // Folds an in-progress squeeze into `cv`, which resets the hasher and
        // leaves `mode` at `Start`.
        self.squeeze_end();
        // Commit the hasher only when it actually holds absorbed input.
        // Otherwise it has just been reset — by `squeeze_end` above, or by an
        // earlier ratchet — and digesting it would overwrite `cv` with the
        // constant `D(D(""))`, discarding every byte absorbed so far. In those
        // states `cv` already commits to the whole history and ratcheting
        // again is a no-op.
        if self.mode == Mode::Absorb {
            // Double hash
            self.cv = <D as Digest>::digest(self.hasher.finalize_reset());
        }
        // Restart the rest of the data
        #[cfg(feature = "zeroize")]
        self.leftovers.zeroize();
        self.leftovers.clear();
        self.mode = Mode::Start;
        self
    }
}

impl<D: BlockSizeUser + Digest + Clone + FixedOutputReset> crate::duplex_sponge::DuplexSpongeInit
    for Hash<D>
{
    /// Absorbs the session identifier as ordinary input
    /// (not the draft's rate-padded `Init`).
    fn init(session_id: &[u8; 32]) -> Self {
        let mut sponge = Self::default();
        sponge.absorb(session_id);
        sponge
    }
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
            // Fixed-width `u64` encoding for cross-architecture portability — see the
            // matching note in `squeeze`.
            Digest::update(&mut squeeze_hasher, (byte_count as u64).to_be_bytes());
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
        // Already-squeezed digest bytes still buffered here are as sensitive as
        // the chaining value: wipe them, do not merely drop the vector.
        self.leftovers.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        Digest::reset(&mut self.hasher);
    }
}

#[cfg(feature = "zeroize")]
impl<D: Clone + Digest + Reset + BlockSizeUser> Drop for Hash<D> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The chaining value and the buffered squeeze output are wiped by
/// [`Zeroize`] in [`Drop`]; the hasher itself is only wiped if `D` wipes on
/// drop, which is why the marker is bounded on `D: ZeroizeOnDrop` rather than
/// asserted for every digest.
#[cfg(feature = "zeroize")]
impl<D: Clone + Digest + Reset + BlockSizeUser + ZeroizeOnDrop> ZeroizeOnDrop for Hash<D> {}

impl<D: BlockSizeUser + Digest + Clone + FixedOutputReset> Default for Hash<D> {
    fn default() -> Self {
        Self {
            hasher: D::new(),
            cv: Output::<D>::default(),
            mode: Mode::Start,
            leftovers: Leftovers::default(),
        }
    }
}

/// Ratcheting must commit to everything absorbed so far, in every mode it can
/// be called from. Ratcheting after a squeeze — or twice in a row — used to
/// digest a hasher that had just been reset, replacing the chaining value with
/// a constant and collapsing the state: two transcripts with nothing in common
/// then produced identical output.
#[cfg(test)]
#[test]
fn ratchet_commits_to_the_absorbed_history() {
    fn output_after(input: &[u8], ratchets_after_squeeze: usize) -> [u8; 32] {
        let mut sho = Hash::<sha2::Sha256>::default();
        sho.absorb(input);
        sho.squeeze(&mut [0u8; 16]);
        for _ in 0..ratchets_after_squeeze {
            sho.ratchet();
        }
        sho.squeeze_array::<32>()
    }

    // One ratchet after a squeeze, and a second redundant one, must both keep
    // distinct histories distinct.
    for ratchets in [1, 2, 3] {
        assert_ne!(
            output_after(b"alice pays bob one coin", ratchets),
            output_after(b"a completely different history", ratchets),
            "state collapsed after {ratchets} ratchet(s)"
        );
    }

    // Ratcheting straight from absorbing already worked; keep it that way.
    let mut absorbed = Hash::<sha2::Sha256>::default();
    absorbed.absorb(b"one");
    absorbed.ratchet();
    let mut other = Hash::<sha2::Sha256>::default();
    other.absorb(b"two");
    other.ratchet();
    assert_ne!(absorbed.squeeze_array::<32>(), other.squeeze_array::<32>());

    // A redundant ratchet is a no-op, not a state change.
    let mut once = Hash::<sha2::Sha256>::default();
    once.absorb(b"input");
    once.ratchet();
    let mut twice = Hash::<sha2::Sha256>::default();
    twice.absorb(b"input");
    twice.ratchet();
    twice.ratchet();
    assert_eq!(once.squeeze_array::<32>(), twice.squeeze_array::<32>());
}

/// Squeezing is iterative: one digest block per iteration, not per stack
/// frame. A recursive implementation overflows the stack well before this
/// size, in release as well as debug.
#[cfg(test)]
#[test]
fn large_squeeze_does_not_recurse() {
    let mut sho = Hash::<sha2::Sha256>::default();
    sho.absorb(b"message");
    let mut output = alloc::vec![0u8; 1 << 20];
    sho.squeeze(&mut output);

    // A chunked squeeze of the same length must be byte-identical: the
    // streaming property has to survive the rewrite.
    let mut chunked = Hash::<sha2::Sha256>::default();
    chunked.absorb(b"message");
    let mut buf = alloc::vec![0u8; 1 << 20];
    for chunk in buf.chunks_mut(Hash::<sha2::Sha256>::DIGEST_SIZE * 2 + 7) {
        chunked.squeeze(chunk);
    }
    assert_eq!(output, buf);
}

/// The buffered squeeze output is now consumed through a cursor rather than
/// drained from the front. Splitting a squeeze at every offset — including
/// offsets that land inside, on, and past a digest boundary — must reproduce
/// the contiguous stream exactly, and interleaving `absorb` and `squeeze_end`
/// must keep the byte counts that feed the transcript unchanged.
#[cfg(test)]
#[test]
fn chunked_squeeze_matches_contiguous_at_every_split() {
    const DIGEST: usize = 32;

    let mut reference = Hash::<sha2::Sha256>::default();
    reference.absorb(b"session");
    let mut expected = [0u8; DIGEST * 4];
    reference.squeeze(&mut expected);

    // Every single split point, so a cursor off by one anywhere in the first
    // four digests is caught.
    for split in 0..=expected.len() {
        let mut sho = Hash::<sha2::Sha256>::default();
        sho.absorb(b"session");
        let mut got = [0u8; DIGEST * 4];
        let (head, tail) = got.split_at_mut(split);
        sho.squeeze(head);
        sho.squeeze(tail);
        assert_eq!(got, expected, "split at {split}");
    }

    // Uneven chunk sizes, including sizes coprime with the digest length.
    for chunk in [1usize, 3, 7, 31, 32, 33, 64, 65] {
        let mut sho = Hash::<sha2::Sha256>::default();
        sho.absorb(b"session");
        let mut got = [0u8; DIGEST * 4];
        for piece in got.chunks_mut(chunk) {
            sho.squeeze(piece);
        }
        assert_eq!(got, expected, "chunk size {chunk}");
    }

    // `squeeze_end` folds the number of bytes read so far into `cv`, and that
    // count is derived from the unconsumed-byte count. Ending a squeeze after
    // a partial digest and absorbing again must therefore stay stable.
    for prefix in [0usize, 1, 31, 32, 33, 63, 64] {
        let mut streaming = Hash::<sha2::Sha256>::default();
        streaming.absorb(b"session");
        let mut scratch = alloc::vec![0u8; prefix];
        streaming.squeeze(&mut scratch);
        streaming.absorb(b"more");
        let mut streamed = [0u8; DIGEST];
        streaming.squeeze(&mut streamed);

        // The same trace, with the prefix squeezed in one-byte pieces: the
        // cursor must leave the state identical to a single squeeze.
        //
        // At `prefix == 0` the loop below would perform *no* squeeze, which is
        // a different trace: unlike an empty absorb, an empty squeeze is not a
        // no-op — it ends absorbing and installs the squeeze prefix. Issue one
        // explicitly so both sides describe the same sequence of operations.
        let mut piecewise = Hash::<sha2::Sha256>::default();
        piecewise.absorb(b"session");
        if prefix == 0 {
            piecewise.squeeze(&mut []);
        }
        for _ in 0..prefix {
            piecewise.squeeze(&mut [0u8; 1]);
        }
        piecewise.absorb(b"more");
        let mut piecemeal = [0u8; DIGEST];
        piecewise.squeeze(&mut piecemeal);

        assert_eq!(streamed, piecemeal, "prefix {prefix}");
    }
}

/// Wiping the state must include the digest bytes buffered from an earlier
/// squeeze, not just the chaining value.
#[cfg(all(test, feature = "zeroize"))]
#[test]
fn zeroize_wipes_buffered_squeeze_output() {
    let mut sho = Hash::<sha2::Sha256>::default();
    sho.absorb(b"message");
    // Squeeze less than one digest, so the remainder stays in `leftovers`.
    sho.squeeze(&mut [0u8; 8]);
    assert!(
        !sho.leftovers.is_empty(),
        "test needs buffered squeeze output"
    );

    Zeroize::zeroize(&mut sho);
    assert!(sho.leftovers.is_empty());
    assert!(sho.cv.iter().all(|&byte| byte == 0));
}

#[cfg(test)]
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
