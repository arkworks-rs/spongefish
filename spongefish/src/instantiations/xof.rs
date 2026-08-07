//! Generic XOF-based duplex sponge implementation.
//!
//! [`XOF`] wraps any extendable-output function implementing
//! [`digest::ExtendableOutput`] with the duplex semantics of
//! draft-irtf-cfrg-fiat-shamir: squeezing finalizes a *copy* of the absorbing
//! state into a reader, consecutive squeezes continue one output stream, a
//! non-empty absorb discards the reader, and absorbing the empty string is a
//! no-op.

use digest::{ExtendableOutput, Update, XofReader};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::DuplexSpongeInterface;

/// Zero bytes to pad an absorb up to a rate boundary.
///
/// 200 bytes is the Keccak-p[1600] state width, an upper bound on the rate of
/// any XOF this module instantiates.
const ZERO_BLOCK: [u8; 200] = [0u8; 200];

/// The sponge rate, in bytes, of an XOF hasher.
///
/// Required by [`XOF`]'s [`DuplexSpongeInit`][crate::duplex_sponge::DuplexSpongeInit]
/// implementation to pad the session identifier to one full rate block.
pub trait XofRate {
    /// The rate in bytes.
    const RATE: usize;
}

#[cfg(feature = "turboshake128")]
impl<const RATE: usize> XofRate for shake::Shake<RATE> {
    const RATE: usize = RATE;
}

#[cfg(feature = "turboshake128")]
impl<const RATE: usize, const DS: u8> XofRate for turboshake::TurboShake<RATE, DS> {
    const RATE: usize = RATE;
}

/// Generic XOF-based duplex sponge implementation.
///
/// This implementation uses any XOF (extendable output function) that implements
/// [`digest::ExtendableOutput`] to provide absorb and squeeze operations
/// compatible with the duplex sponge interface.
pub struct XOF<H: ExtendableOutput> {
    /// The current XOF hasher state
    hasher: H,
    /// XOF reader for squeeze operations (None = absorbing, Some = squeezing)
    xof_reader: Option<H::Reader>,
}

impl<H> Clone for XOF<H>
where
    H: ExtendableOutput + Clone,
    H::Reader: Clone,
{
    fn clone(&self) -> Self {
        Self {
            hasher: self.hasher.clone(),
            xof_reader: self.xof_reader.clone(),
        }
    }
}

impl<H> DuplexSpongeInterface for XOF<H>
where
    H: ExtendableOutput + Clone + Default,
    H::Reader: Clone,
{
    type U = u8;

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        if !input.is_empty() {
            self.xof_reader = None;
            Update::update(&mut self.hasher, input);
        }
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        let reader = self
            .xof_reader
            .get_or_insert_with(|| ExtendableOutput::finalize_xof(self.hasher.clone()));
        XofReader::read(reader, output);

        self
    }
}

impl<H> crate::duplex_sponge::DuplexSpongeInit for XOF<H>
where
    H: ExtendableOutput + Clone + Default + XofRate,
    H::Reader: Clone,
{
    /// The draft's `Init(session_id)`: absorbs the identifier padded with zero
    /// bytes to one full rate block ([`XofRate::RATE`]), so that subsequent
    /// input starts on a fresh block boundary.
    fn init(session_id: &[u8; 32]) -> Self {
        const { assert!(H::RATE >= 32 && H::RATE <= ZERO_BLOCK.len()) }
        let mut sponge = Self::default();
        sponge.absorb(session_id);
        sponge.absorb(&ZERO_BLOCK[..H::RATE - 32]);
        sponge
    }

    /// Zero-pads each mix to a full rate block. Assumes the absorb position is
    /// block-aligned on entry, which holds when the sponge is only touched
    /// through `init` and `absorb_block`.
    fn absorb_block(&mut self, input: &[u8]) {
        self.absorb(input);
        let rem = input.len() % H::RATE;
        if rem != 0 {
            self.absorb(&ZERO_BLOCK[..H::RATE - rem]);
        }
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
    }
}

/// Backed by the fields' own `Drop` impls, so both of them must wipe: the
/// bound covers the reader as well as the hasher, rather than assuming it.
///
/// `TurboShake128` — the default `StdHash` — satisfies both bounds. `Shake128`
/// does not carry this marker: the reader of `shake 0.1.0` wipes its state on
/// drop but does not declare `ZeroizeOnDrop`, and this crate will not assert a
/// guarantee the type system cannot check.
#[cfg(feature = "zeroize")]
impl<H> ZeroizeOnDrop for XOF<H>
where
    H: ExtendableOutput + ZeroizeOnDrop,
    H::Reader: ZeroizeOnDrop,
{
}

impl<H> Default for XOF<H>
where
    H: ExtendableOutput + Default,
{
    fn default() -> Self {
        Self {
            hasher: H::default(),
            xof_reader: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::XOF;
    #[cfg(feature = "turboshake128")]
    use crate::duplex_sponge::DuplexSpongeInit;
    use crate::duplex_sponge::DuplexSpongeInterface;

    #[cfg(feature = "turboshake128")]
    type Shake128 = crate::instantiations::Shake128;
    #[cfg(feature = "turboshake128")]
    type TurboShake128 = crate::instantiations::TurboShake128;

    /// The SHAKE128 instantiation must produce the same bytes as evaluating
    /// the SHAKE128 XOF over
    /// `session_id || zeros(168 - 32) || absorbed input` — the draft's defining
    /// equation — for inputs crossing zero, one, and several block boundaries.
    #[cfg(feature = "turboshake128")]
    #[test]
    fn matches_shake128_xof() {
        use shake::{ExtendableOutput, Update, XofReader};

        let session_id = [7u8; 32];
        for input_len in [0usize, 1, 135, 136, 137, 167, 168, 335, 400, 1000] {
            let input: alloc::vec::Vec<u8> = (0..input_len).map(|i| i as u8).collect();

            let mut sponge = Shake128::init(&session_id);
            let mut got = alloc::vec![0u8; 333];
            sponge.absorb(&input).squeeze(&mut got);

            let mut xof = shake::Shake128::default();
            xof.update(&session_id);
            xof.update(&[0u8; 168 - 32]);
            xof.update(&input);
            let mut expected = alloc::vec![0u8; 333];
            let mut reader = xof.finalize_xof();
            XofReader::read(&mut reader, &mut expected);

            assert_eq!(got, expected, "input_len {input_len}");
        }
    }

    /// Absorbing is associative, the empty absorb is a no-op that does not reset
    /// the output stream, and a non-empty absorb does reset it.
    #[cfg(feature = "turboshake128")]
    #[test]
    fn absorb_and_stream_semantics() {
        let sid = [3u8; 32];

        let mut split = TurboShake128::init(&sid);
        split.absorb(b"hello ").absorb(b"world");
        let mut joined = TurboShake128::init(&sid);
        joined.absorb(b"hello world");
        assert_eq!(split.squeeze_array::<32>(), joined.squeeze_array::<32>());

        let mut streaming = Shake128::init(&sid);
        streaming.absorb(b"msg");
        let mut all = [0u8; 64];
        Shake128::init(&sid).absorb(b"msg").squeeze(&mut all);
        let (mut lo, mut hi) = ([0u8; 32], [0u8; 32]);
        streaming.squeeze(&mut lo).squeeze(&mut hi);
        assert_eq!([lo, hi].concat(), all);

        let mut with_empty = Shake128::init(&sid);
        with_empty.absorb(b"msg").squeeze(&mut lo);
        with_empty.absorb(b"").squeeze(&mut hi);
        assert_eq!([lo, hi].concat(), all);

        let mut reset = Shake128::init(&sid);
        reset.absorb(b"msg").squeeze(&mut [0u8; 32]).absorb(b"more");
        let mut after_reset = [0u8; 32];
        reset.squeeze(&mut after_reset);
        let mut expected = Shake128::init(&sid);
        let mut expected_out = [0u8; 32];
        expected.absorb(b"msgmore").squeeze(&mut expected_out);
        assert_eq!(after_reset, expected_out);
    }

    #[allow(unused)]
    fn assert_clone_preserves_squeeze_position<H>()
    where
        H: digest::ExtendableOutput + Clone + Default,
        H::Reader: Clone,
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

    #[cfg(feature = "turboshake128")]
    #[test]
    fn shake128_clone_preserves_squeeze_position() {
        assert_clone_preserves_squeeze_position::<shake::Shake128>();
    }

    #[cfg(feature = "turboshake128")]
    #[test]
    fn turboshake128_clone_preserves_squeeze_position() {
        assert_clone_preserves_squeeze_position::<::turboshake::TurboShake128>();
    }
}
