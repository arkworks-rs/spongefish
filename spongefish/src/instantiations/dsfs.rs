//! Duplex sponges of [draft-irtf-cfrg-fiat-shamir]: SHAKE128 and TurboSHAKE128.
//!
//! These are the two instantiations specified by the draft. Both are built on the
//! Keccak permutation over a 200-byte (1600-bit) state, with a rate of `R = 168`
//! bytes and a capacity of 32 bytes, and both follow **XOF semantics**:
//!
//! - [`KeccakDuplexSponge::new`] seeds the state by absorbing the 32-byte session
//!   identifier padded with `R - 32` zero bytes, so that subsequent input starts on
//!   a fresh rate-block boundary;
//! - `Squeeze` finalizes a *copy* of the absorbing state (applying the XOF padding)
//!   and reads from it; consecutive squeezes continue one output stream;
//! - a non-empty `Absorb` discards the output stream (subsequent squeezes read the
//!   XOF of the full absorbed prefix); absorbing the empty string is a no-op and
//!   does **not** reset the stream.
//!
//! This matches the byte-for-byte behavior of evaluating the XOF over the whole
//! absorbed prefix at every squeeze, at incremental (non-quadratic) cost.
//!
//! The permutation is dispatched at runtime through the [`keccak`] crate (hardware
//! SHA3 instructions on aarch64, portable fallback elsewhere). A `const` software
//! permutation is used for compile-time evaluation: [`KeccakDuplexSponge::new`] and
//! [`KeccakDuplexSponge::derive_session_id`] are `const fn`, so applications with a
//! static tag can precompute the seeded sponge state at compile time:
//!
//! ```
//! use spongefish::instantiations::dsfs::Shake128;
//!
//! static SESSION_ID: [u8; 32] = Shake128::derive_session_id(b"EXAMPLE-V00-DSFS-TS128");
//! static SEEDED: Shake128 = Shake128::new(&SESSION_ID);
//! let mut sponge = SEEDED.clone();
//! let mut challenge = [0u8; 32];
//! sponge.absorb(b"instance").squeeze(&mut challenge);
//! ```
//!
//! [draft-irtf-cfrg-fiat-shamir]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/

use core::fmt;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The rate of the sponge in bytes: 168 bytes for both SHAKE128 and TurboSHAKE128.
pub const RATE: usize = 168;

/// The byte length of session identifiers.
pub const SESSION_ID_LEN: usize = 32;

/// The XOF padding byte. For SHAKE128 this is the four-bit suffix `1111`
/// followed by the first bit of `pad10*1`; for TurboSHAKE128 it is the
/// domain-separation byte, fixed to `D = 0x1F` by the draft.
const PAD: u8 = 0x1F;

/// The final byte of the `pad10*1` padding rule.
const PAD_END: u8 = 0x80;

/// The SHAKE128 duplex sponge of draft-irtf-cfrg-fiat-shamir
/// (`Keccak-f[1600]`, 24 rounds).
pub type Shake128 = KeccakDuplexSponge<24>;

/// The TurboSHAKE128 duplex sponge of draft-irtf-cfrg-fiat-shamir
/// (`Keccak-p[1600, 12]`, RFC 9861, `D = 0x1F`).
pub type TurboShake128 = KeccakDuplexSponge<12>;

/// A duplex sponge with XOF semantics over `Keccak-p[1600, ROUNDS]`.
///
/// `ROUNDS = 24` is SHAKE128 ([`Shake128`]); `ROUNDS = 12` is TurboSHAKE128
/// ([`TurboShake128`]). See the [module documentation][self] for semantics.
#[derive(Clone)]
pub struct KeccakDuplexSponge<const ROUNDS: usize> {
    /// The absorbing state, as 25 little-endian 64-bit lanes.
    state: [u64; 25],
    /// Byte position of the next absorbed byte within the rate, in `[0, RATE)`.
    absorb_pos: usize,
    /// The output stream, present while in the squeezing phase.
    reader: Option<SqueezeReader>,
}

/// The squeezing half of the sponge: a finalized copy of the absorbing state.
#[derive(Clone)]
struct SqueezeReader {
    state: [u64; 25],
    /// Byte position of the next squeezed byte within the rate, in `[0, RATE]`.
    pos: usize,
}

impl<const ROUNDS: usize> KeccakDuplexSponge<ROUNDS> {
    /// `Init(session_id)`: seed the sponge by absorbing the 32-byte session
    /// identifier followed by `RATE - 32` zero bytes (exactly one rate block).
    ///
    /// This is a `const fn`: with a static session identifier the seeded state is
    /// computed at compile time (see the [module documentation][self]).
    #[must_use]
    pub const fn new(session_id: &[u8; SESSION_ID_LEN]) -> Self {
        let mut state = [0u64; 25];
        // Absorbing `session_id || zeros(RATE - 32)` into the all-zero state:
        // XORing zero bytes is a no-op, so only the identifier bytes are written,
        // followed by the permutation for the completed rate block.
        let mut i = 0;
        while i < SESSION_ID_LEN {
            state[i / 8] ^= (session_id[i] as u64) << (8 * (i % 8));
            i += 1;
        }
        keccak_p1600_soft(&mut state, ROUNDS);
        Self {
            state,
            absorb_pos: 0,
            reader: None,
        }
    }

    /// `DeriveSessionID(tag)` of draft-irtf-cfrg-fiat-shamir: derive a 32-byte
    /// session identifier from an application-chosen tag, using this duplex
    /// sponge seeded with the domain separator `"irtf-cfrg-fiat-shamir/session-id"`.
    ///
    /// This is a `const fn`: static tags are derived at compile time.
    #[must_use]
    pub const fn derive_session_id(tag: &[u8]) -> [u8; SESSION_ID_LEN] {
        let mut sponge = Self::new(b"irtf-cfrg-fiat-shamir/session-id");
        // Absorb the tag, byte by byte (const context; not performance-relevant).
        let mut i = 0;
        while i < tag.len() {
            sponge.state[sponge.absorb_pos / 8] ^=
                (tag[i] as u64) << (8 * (sponge.absorb_pos % 8));
            sponge.absorb_pos += 1;
            if sponge.absorb_pos == RATE {
                keccak_p1600_soft(&mut sponge.state, ROUNDS);
                sponge.absorb_pos = 0;
            }
            i += 1;
        }
        // Finalize a copy of the absorbing state and read 32 bytes.
        let mut out_state = sponge.state;
        out_state[sponge.absorb_pos / 8] ^= (PAD as u64) << (8 * (sponge.absorb_pos % 8));
        out_state[(RATE - 1) / 8] ^= (PAD_END as u64) << (8 * ((RATE - 1) % 8));
        keccak_p1600_soft(&mut out_state, ROUNDS);
        let mut out = [0u8; SESSION_ID_LEN];
        let mut i = 0;
        while i < SESSION_ID_LEN {
            out[i] = (out_state[i / 8] >> (8 * (i % 8))) as u8;
            i += 1;
        }
        out
    }

    /// Absorb a byte string into the state.
    ///
    /// Absorbing is associative (`absorb(x); absorb(y)` equals `absorb(x || y)`),
    /// and absorbing the empty string leaves the state unchanged — including the
    /// output stream, which only a *non-empty* absorb resets.
    pub fn absorb(&mut self, input: &[u8]) -> &mut Self {
        if input.is_empty() {
            return self;
        }
        self.reader = None;
        let mut input = input;
        while !input.is_empty() {
            let take = usize::min(RATE - self.absorb_pos, input.len());
            let (chunk, rest) = input.split_at(take);
            xor_bytes_at(&mut self.state, self.absorb_pos, chunk);
            self.absorb_pos += take;
            input = rest;
            if self.absorb_pos == RATE {
                permute::<ROUNDS>(&mut self.state);
                self.absorb_pos = 0;
            }
        }
        self
    }

    /// Squeeze the next `output.len()` bytes of the XOF output stream computed
    /// over the absorbed input. Consecutive squeezes continue one stream.
    pub fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        if output.is_empty() {
            return self;
        }
        if self.reader.is_none() {
            // Finalize a copy of the absorbing state with the XOF padding.
            let mut state = self.state;
            xor_byte(&mut state, self.absorb_pos, PAD);
            xor_byte(&mut state, RATE - 1, PAD_END);
            permute::<ROUNDS>(&mut state);
            self.reader = Some(SqueezeReader { state, pos: 0 });
        }
        let reader = self.reader.as_mut().expect("reader initialized above");
        let mut output = output;
        loop {
            let take = usize::min(RATE - reader.pos, output.len());
            let (chunk, rest) = output.split_at_mut(take);
            read_bytes_at(&reader.state, reader.pos, chunk);
            reader.pos += take;
            output = rest;
            if output.is_empty() {
                return self;
            }
            permute::<ROUNDS>(&mut reader.state);
            reader.pos = 0;
        }
    }
}

impl<const ROUNDS: usize> crate::duplex_sponge::DuplexSpongeInterface
    for KeccakDuplexSponge<ROUNDS>
{
    type U = u8;

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        Self::absorb(self, input)
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        Self::squeeze(self, output)
    }

    fn ratchet(&mut self) -> &mut Self {
        unimplemented!("ratchet is not part of draft-irtf-cfrg-fiat-shamir")
    }
}

impl<const ROUNDS: usize> fmt::Debug for KeccakDuplexSponge<ROUNDS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The state is deliberately not printed: for the prover's private
        // randomness sponge it is secret material.
        write!(f, "KeccakDuplexSponge<{ROUNDS}>")
    }
}

#[cfg(feature = "zeroize")]
impl<const ROUNDS: usize> Zeroize for KeccakDuplexSponge<ROUNDS> {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.absorb_pos.zeroize();
        if let Some(reader) = &mut self.reader {
            reader.state.zeroize();
            reader.pos.zeroize();
        }
        self.reader = None;
    }
}

#[cfg(feature = "zeroize")]
impl<const ROUNDS: usize> ZeroizeOnDrop for KeccakDuplexSponge<ROUNDS> {}

/// Run `Keccak-p[1600, ROUNDS]`, dispatched through the [`keccak`] crate
/// (hardware SHA3 on aarch64 when available, portable software otherwise).
#[inline]
fn permute<const ROUNDS: usize>(state: &mut [u64; 25]) {
    ::keccak::Keccak::new().with_p1600::<ROUNDS>(|p1600| p1600(state));
}

/// XOR a single byte into the lane state at byte offset `pos`.
#[inline]
const fn xor_byte(state: &mut [u64; 25], pos: usize, byte: u8) {
    state[pos / 8] ^= (byte as u64) << (8 * (pos % 8));
}

/// XOR `bytes` into the lane state starting at byte offset `pos`,
/// using whole-lane operations for the aligned middle.
fn xor_bytes_at(state: &mut [u64; 25], mut pos: usize, mut bytes: &[u8]) {
    while !pos.is_multiple_of(8) && !bytes.is_empty() {
        xor_byte(state, pos, bytes[0]);
        pos += 1;
        bytes = &bytes[1..];
    }
    let mut lanes = bytes.chunks_exact(8);
    for lane in &mut lanes {
        state[pos / 8] ^= u64::from_le_bytes(lane.try_into().expect("8-byte chunk"));
        pos += 8;
    }
    for &byte in lanes.remainder() {
        xor_byte(state, pos, byte);
        pos += 1;
    }
}

/// Copy bytes out of the lane state starting at byte offset `pos`,
/// using whole-lane operations for the aligned middle.
fn read_bytes_at(state: &[u64; 25], mut pos: usize, out: &mut [u8]) {
    let mut out = out;
    while !pos.is_multiple_of(8) && !out.is_empty() {
        out[0] = (state[pos / 8] >> (8 * (pos % 8))) as u8;
        pos += 1;
        out = &mut out[1..];
    }
    let mut lanes = out.chunks_exact_mut(8);
    for lane in &mut lanes {
        lane.copy_from_slice(&state[pos / 8].to_le_bytes());
        pos += 8;
    }
    for byte in lanes.into_remainder() {
        *byte = (state[pos / 8] >> (8 * (pos % 8))) as u8;
        pos += 1;
    }
}

/// The Keccak round constants for `iota`, indexed by round `0..24`.
/// `Keccak-p[1600, nr]` uses the **last** `nr` rounds (FIPS 202 §3.4, RFC 9861).
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets for the combined `rho`+`pi` step, in `pi`-walk order.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane destinations for the combined `rho`+`pi` step.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Constant-evaluable software `Keccak-p[1600, rounds]` (the last `rounds` of
/// the 24 `Keccak-f[1600]` rounds).
///
/// Used for `const` precomputation ([`KeccakDuplexSponge::new`],
/// [`KeccakDuplexSponge::derive_session_id`]); the runtime hot path uses the
/// dispatched backend in [`permute`]. A unit test pins the two byte-identical.
pub(crate) const fn keccak_p1600_soft(state: &mut [u64; 25], rounds: usize) {
    assert!(rounds <= 24);
    let mut round = 24 - rounds;
    while round < 24 {
        // theta
        let mut parity = [0u64; 5];
        let mut x = 0;
        while x < 5 {
            parity[x] =
                state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            x += 1;
        }
        let mut x = 0;
        while x < 5 {
            let d = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
            let mut y = 0;
            while y < 25 {
                state[x + y] ^= d;
                y += 5;
            }
            x += 1;
        }
        // rho and pi
        let mut lane = state[1];
        let mut i = 0;
        while i < 24 {
            let j = PI[i];
            let next = state[j];
            state[j] = lane.rotate_left(RHO[i]);
            lane = next;
            i += 1;
        }
        // chi
        let mut y = 0;
        while y < 25 {
            let row = [
                state[y],
                state[y + 1],
                state[y + 2],
                state[y + 3],
                state[y + 4],
            ];
            let mut x = 0;
            while x < 5 {
                state[y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
                x += 1;
            }
            y += 5;
        }
        // iota
        state[0] ^= ROUND_CONSTANTS[round];
        round += 1;
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    /// A fixed pseudo-random state for permutation equivalence tests.
    fn scrambled_state(seed: u64) -> [u64; 25] {
        let mut x = seed | 1;
        core::array::from_fn(|_| {
            // xorshift64
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        })
    }

    /// The const software permutation must be byte-identical to the dispatched
    /// backend, for both the 24-round and the 12-round variants.
    #[test]
    fn soft_permutation_matches_dispatched_backend() {
        for seed in [1, 42, 0xdead_beef, u64::MAX] {
            let mut soft24 = scrambled_state(seed);
            let mut fast24 = soft24;
            keccak_p1600_soft(&mut soft24, 24);
            permute::<24>(&mut fast24);
            assert_eq!(soft24, fast24, "24-round mismatch (seed {seed})");

            let mut soft12 = scrambled_state(seed);
            let mut fast12 = soft12;
            keccak_p1600_soft(&mut soft12, 12);
            permute::<12>(&mut fast12);
            assert_eq!(soft12, fast12, "12-round mismatch (seed {seed})");
        }
    }

    /// The sponge must produce the same bytes as evaluating the SHAKE128 XOF over
    /// `session_id || zeros(RATE - 32) || absorbed input` — the draft's defining
    /// equation — for inputs crossing zero, one, and several block boundaries.
    #[cfg(feature = "sha3")]
    #[test]
    fn matches_shake128_xof() {
        use sha3::digest::{ExtendableOutput, Update, XofReader};

        let session_id = [7u8; SESSION_ID_LEN];
        for input_len in [0usize, 1, 135, 136, 137, 168, 400, 1000] {
            let input: Vec<u8> = (0..input_len).map(|i| i as u8).collect();

            let mut sponge = Shake128::new(&session_id);
            let mut got = vec![0u8; 333];
            sponge.absorb(&input).squeeze(&mut got);

            let mut xof = sha3::Shake128::default();
            xof.update(&session_id);
            xof.update(&[0u8; RATE - SESSION_ID_LEN]);
            xof.update(&input);
            let mut expected = vec![0u8; 333];
            xof.finalize_xof().read(&mut expected);

            assert_eq!(got, expected, "input_len {input_len}");
        }
    }

    /// Absorbing is associative, the empty absorb is a no-op that does not reset
    /// the output stream, and a non-empty absorb does reset it.
    #[test]
    fn absorb_and_stream_semantics() {
        let sid = [3u8; SESSION_ID_LEN];

        // absorb(x); absorb(y) == absorb(x || y)
        let mut split = TurboShake128::new(&sid);
        split.absorb(b"hello ").absorb(b"world");
        let mut joined = TurboShake128::new(&sid);
        joined.absorb(b"hello world");
        assert_eq!(split.squeeze_pair(), joined.squeeze_pair());

        // squeeze; squeeze continues one stream
        let mut streaming = Shake128::new(&sid);
        streaming.absorb(b"msg");
        let mut all = [0u8; 64];
        Shake128::new(&sid).absorb(b"msg").squeeze(&mut all);
        let (mut lo, mut hi) = ([0u8; 32], [0u8; 32]);
        streaming.squeeze(&mut lo).squeeze(&mut hi);
        assert_eq!([lo, hi].concat(), all);

        // absorb("") between squeezes does not reset the stream
        let mut with_empty = Shake128::new(&sid);
        with_empty.absorb(b"msg").squeeze(&mut lo);
        with_empty.absorb(b"").squeeze(&mut hi);
        assert_eq!([lo, hi].concat(), all);

        // a non-empty absorb resets: the next squeeze reads the full-prefix XOF
        let mut reset = Shake128::new(&sid);
        reset.absorb(b"msg").squeeze(&mut [0u8; 32]).absorb(b"more");
        let mut after_reset = [0u8; 32];
        reset.squeeze(&mut after_reset);
        let mut expected = Shake128::new(&sid);
        let mut expected_out = [0u8; 32];
        expected.absorb(b"msgmore").squeeze(&mut expected_out);
        assert_eq!(after_reset, expected_out);
    }

    impl<const ROUNDS: usize> KeccakDuplexSponge<ROUNDS> {
        fn squeeze_pair(&mut self) -> [u8; 32] {
            let mut out = [0u8; 32];
            self.squeeze(&mut out);
            out
        }
    }

    /// `new` and `derive_session_id` are const-evaluable, and the compile-time
    /// values agree with the runtime path.
    #[test]
    fn const_precomputation_matches_runtime() {
        const TAG: &[u8] = b"spongefish-const-eval-test";
        const SID: [u8; 32] = Shake128::derive_session_id(TAG);
        static SEEDED: Shake128 = Shake128::new(&SID);

        assert_eq!(SID, Shake128::derive_session_id(TAG));
        let mut a = SEEDED.clone();
        let mut b = Shake128::new(&SID);
        a.absorb(b"x");
        b.absorb(b"x");
        assert_eq!(a.squeeze_pair(), b.squeeze_pair());
    }
}
