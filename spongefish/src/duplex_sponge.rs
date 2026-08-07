//! This module defines the duplex sponge construction that can absorb and squeeze data.
//!
//! Hashes can operate over generic elements called [`Unit`], be they field elements, bytes, or any other data structure.
//! Roughly speaking, a [`Unit`] requires only [`Clone`] and [`Sized`], and has a
//! special element [`Unit::ZERO`] that denotes the default, neutral value to write on initialization and deletion.
//!
//! A [`DuplexSpongeInterface`] is the interface providing basic absorb/squeeze functions over [`Unit`]s.
//! On top of which we build the prover and verifier state.
//!
//! Many instantiations of [`DuplexSpongeInterface`] are provided in this crate.
//! While a formal analysis exists only for ideal permutations, i.e. a [`Permutation`] used with the [`DuplexSponge`] struct,
//! we also provide additional examples from generic XOFs implementing [`digest::ExtendableOutput`] and hash functions implementing [`digest::Digest`].

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A trait denoting the requirements for the elements of the alphabet.
///
/// ```
/// # #[cfg(feature = "derive")]
/// # {
/// use spongefish::Unit;
///
/// #[derive(Clone, Debug, Unit, PartialEq, Eq)]
/// pub struct Rgb(pub u8, pub u8, pub u8);
///
/// assert_eq!(Rgb::ZERO, Rgb(0, 0, 0))
/// # }
/// ```
pub trait Unit: Clone + Sized {
    /// The zero element.
    const ZERO: Self;
}

/// The embedding of byte strings into a sponge alphabet.
///
/// Some inputs are byte strings whatever the sponge's alphabet is,  above all the
/// 32-byte session identifier, which [draft-irtf-cfrg-fiat-shamir][FS] derives
/// with a byte-oriented hash and hands to `Init`.
///
/// # Safety
///
/// The map **MUST** be injective on the byte lengths it is used at. It need
/// not be prefix-free. The session identifier is always exactly 32 bytes,
/// but a caller absorbing variable-length byte strings through it must length-
/// prefix them itself.
///
/// [FS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
pub trait UnitFromBytes: Unit {
    /// Reads `bytes` as a string of units.
    fn encode_bytes(bytes: &[u8]) -> impl AsRef<[Self]>;
}

/// Over bytes the embedding is the identity, and borrows rather than
/// allocating: a byte sponge pays nothing for this indirection.
impl UnitFromBytes for u8 {
    fn encode_bytes(bytes: &[u8]) -> impl AsRef<[Self]> {
        bytes
    }
}

macro_rules! impl_integer_unit {
    ($t:ty) => {
        impl Unit for $t {
            const ZERO: Self = 0;
        }
    };
}

impl_integer_unit!(u8);
impl_integer_unit!(u32);
impl_integer_unit!(u64);
impl_integer_unit!(u128);
// NOTE: deliberately no `usize` impl (32- vs 64-bit targets).

/// A [`DuplexSpongeInterface`] is an abstract interface for absorbing and squeezing elements implementing [`Unit`].
///
/// **HAZARD**: Don't implement this trait unless you know what you are doing.
/// Consider using the sponges already provided by this library.
pub trait DuplexSpongeInterface: Clone {
    /// The type of elements over which this duplex sponge operates.
    ///
    /// In [[CO25]], this is called "alphabet".
    /// The alphabet must be a non-empty set.
    ///
    /// [CO25]: https://eprint.iacr.org/2025/536.pdf
    type U: Unit;

    /// Absorbs new elements in the sponge.
    ///
    /// Calls to absorb are meant to be associative:
    /// calling this function multiple times is equivalent to calling it once
    /// on the concatenated inputs.
    fn absorb(&mut self, input: &[Self::U]) -> &mut Self;

    /// Squeezes out new elements.
    ///
    /// Calls to this function are meant to be associative:
    /// calling this function multiple times is equivalent to calling it once
    /// on a larger output array.
    ///
    /// Whether squeezing affects a subsequent absorb, and if so at what
    /// granularity, is left to the implementation. The session identifier MUST
    /// take care of the absorb/squeeze pattern.
    fn squeeze(&mut self, output: &mut [Self::U]) -> &mut Self;

    /// Squeeze a fixed-length array of size `LEN`.
    fn squeeze_array<const LEN: usize>(&mut self) -> [Self::U; LEN] {
        let mut output = [Self::U::ZERO; LEN];
        self.squeeze(&mut output);
        output
    }

    /// Squeeze `len` elements into a freshly allocated array.
    fn squeeze_boxed(&mut self, len: usize) -> alloc::boxed::Box<[Self::U]> {
        let mut output = alloc::vec![Self::U::ZERO; len];
        self.squeeze(&mut output);
        output.into_boxed_slice()
    }
}

/// A permutation operating over an array of `WIDTH` [`Unit`]s.
pub trait Permutation<const WIDTH: usize>: Clone {
    /// The [`Unit`] defining the alphabet for the permutation function.
    type U: Unit;

    /// The permutation function, evaluated in place.
    ///
    /// This is the required method because it is the shape every real
    /// permutation has: the state is mixed where it lies. A by-value
    /// [`Permutation::permute`] is derived from it, not the other way around.
    fn permute_mut(&self, state: &mut [Self::U; WIDTH]);

    /// By-value evaluation of [`Permutation::permute_mut`].
    fn permute(&self, state: &[Self::U; WIDTH]) -> [Self::U; WIDTH] {
        let mut permuted = state.clone();
        self.permute_mut(&mut permuted);
        permuted
    }
}

/// The duplex sponge construction from [[CO25], Construction 3.3].
///
/// Based on a [`Permutation`] for `WIDTH` elements, with rate `RATE`.
///
/// # Instantiation
///
/// The rate segment is written in the first `RATE` units of the sponge;
/// the capacity segment is written in the last `WIDTH`-`RATE` units of the sponge.
///
/// # Panics
///
/// Instantiation will panic if `WIDTH` is less than or equal to `RATE`, or if `RATE` is zero.
///
/// [CO25]: https://eprint.iacr.org/2025/536.pdf
#[derive(Clone, PartialEq, Eq)]
pub struct DuplexSponge<P, const WIDTH: usize, const RATE: usize>
where
    P: Permutation<WIDTH>,
{
    permutation: P,
    permutation_state: [P::U; WIDTH],
    absorb_pos: usize,
    squeeze_pos: usize,
}

impl<P, const WIDTH: usize, const RATE: usize> DuplexSponge<P, WIDTH, RATE>
where
    P: Permutation<WIDTH>,
{
    fn with_permutation(permutation: P) -> Self {
        assert!(WIDTH > RATE, "capacity segment must be non-empty");
        assert!(RATE > 0, "rate segment must be non-empty");
        Self {
            permutation,
            permutation_state: [P::U::ZERO; WIDTH],
            absorb_pos: 0,
            squeeze_pos: RATE,
        }
    }
}

impl<P, const WIDTH: usize, const RATE: usize> Default for DuplexSponge<P, WIDTH, RATE>
where
    P: Permutation<WIDTH> + Default,
{
    fn default() -> Self {
        P::default().into()
    }
}

impl<P, const WIDTH: usize, const RATE: usize> From<P> for DuplexSponge<P, WIDTH, RATE>
where
    P: Permutation<WIDTH>,
{
    fn from(value: P) -> Self {
        Self::with_permutation(value)
    }
}

#[cfg(feature = "zeroize")]
impl<P, const WIDTH: usize, const RATE: usize> Zeroize for DuplexSponge<P, WIDTH, RATE>
where
    P: Permutation<WIDTH> + Clone,
{
    fn zeroize(&mut self) {
        self.absorb_pos.zeroize();
        // `Unit` does not require `Zeroize`, so the state is cleared with a
        // plain fill; the fence keeps the optimizer from eliding the writes.
        self.permutation_state.as_mut().fill(P::U::ZERO);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.squeeze_pos.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P, const WIDTH: usize, const RATE: usize> Drop for DuplexSponge<P, WIDTH, RATE>
where
    P: Permutation<WIDTH>,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P, const WIDTH: usize, const RATE: usize> ZeroizeOnDrop for DuplexSponge<P, WIDTH, RATE> where
    P: Permutation<WIDTH>
{
}

impl<P, const WIDTH: usize, const RATE: usize> DuplexSpongeInterface
    for DuplexSponge<P, WIDTH, RATE>
where
    P: Permutation<WIDTH>,
{
    type U = P::U;

    fn absorb(&mut self, mut input: &[Self::U]) -> &mut Self {
        // Absorbing is associative, so absorbing the empty string is the
        // identity: it must not end an in-progress squeeze stream. Returning
        // early keeps this construction in step with the XOF instantiations,
        // which are no-ops on the empty input.
        if input.is_empty() {
            return self;
        }
        self.squeeze_pos = RATE;

        while !input.is_empty() {
            if self.absorb_pos == RATE {
                self.permutation.permute_mut(&mut self.permutation_state);
                self.absorb_pos = 0;
            } else {
                debug_assert!(self.absorb_pos < RATE);
                let chunk_len = usize::min(input.len(), RATE - self.absorb_pos);
                let (chunk, rest) = input.split_at(chunk_len);

                self.permutation_state[self.absorb_pos..self.absorb_pos + chunk_len]
                    .clone_from_slice(chunk);
                self.absorb_pos += chunk_len;
                input = rest;
            }
        }
        self
    }

    fn squeeze(&mut self, mut output: &mut [Self::U]) -> &mut Self {
        if output.is_empty() {
            return self;
        }
        self.absorb_pos = 0;

        // Iterative by construction: one rate block per iteration. A recursive
        // formulation costs one stack frame per block and overflows on large
        // squeezes.
        while !output.is_empty() {
            if self.squeeze_pos == RATE {
                self.squeeze_pos = 0;
                self.permutation.permute_mut(&mut self.permutation_state);
            }

            debug_assert!(self.squeeze_pos < RATE);
            let chunk_len = usize::min(output.len(), RATE - self.squeeze_pos);
            let (chunk, rest) = output.split_at_mut(chunk_len);
            chunk.clone_from_slice(
                &self.permutation_state[self.squeeze_pos..self.squeeze_pos + chunk_len],
            );
            self.squeeze_pos += chunk_len;
            output = rest;
        }
        self
    }
}

/// Duplex sponges that can be seeded from a 32-byte session identifier.
///
/// For the draft-irtf-cfrg-fiat-shamir suites
/// ([`Shake128`][crate::instantiations::Shake128],
/// [`TurboShake128`][crate::instantiations::TurboShake128]) this is the
/// draft's `Init(session_id)`: the identifier is absorbed padded with zeros to
/// fill exactly one rate block. Other instantiations absorb the identifier
/// under their own conventions and are **not** draft-compliant.
///
/// # Alphabets
///
/// A session identifier is a byte string, whatever the sponge's alphabet: the
/// draft derives it from an application tag with a byte-oriented hash, and it
/// is the caller who supplies it. A sponge over a non-byte alphabet therefore
/// needs one more thing — a way to read those 32 bytes as units — which is
/// [`UnitFromBytes`]. See the blanket implementation on [`DuplexSponge`]
/// below.
pub trait DuplexSpongeInit: DuplexSpongeInterface {
    /// Create a new duplex sponge state, seeded by the 32-byte `session_id`.
    fn init(session_id: &[u8; 32]) -> Self;

    /// Absorb auxiliary input such as RNG entropy mixes.
    ///
    /// Constructions with a block structure (the XOF suites) zero-pad the
    /// input to the next rate boundary so it is permuted before any further
    /// operation.
    fn absorb_block(&mut self, input: &[Self::U]) {
        self.absorb(input);
    }
}

/// The overwrite-mode duplex sponge is seeded over **any** alphabet that a
/// byte string embeds into: the session identifier is absorbed as ordinary
/// input, through [`UnitFromBytes`].
///
/// Over bytes that embedding is the identity and borrows rather than
/// allocating, so this is the plain `absorb(session_id)` it replaces — same
/// transcript, same cost. Over a field alphabet, the crate defining the
/// [`Unit`] defines the embedding too (see `spongefish-circuit` for BabyBear).
impl<P, const WIDTH: usize, const RATE: usize> DuplexSpongeInit for DuplexSponge<P, WIDTH, RATE>
where
    P: Permutation<WIDTH> + Default,
    P::U: UnitFromBytes,
{
    /// Absorbs the session identifier as ordinary input (overwrite-mode
    /// convention; not the draft's `Init`).
    fn init(session_id: &[u8; 32]) -> Self {
        let mut sponge = Self::with_permutation(P::default());
        sponge.absorb(P::U::encode_bytes(session_id).as_ref());
        sponge
    }
}

#[cfg(test)]
mod tests {
    use super::{DuplexSponge, DuplexSpongeInterface, Permutation};

    const WIDTH: usize = 16;
    const RATE: usize = 8;

    /// A toy bijection over the state, enough to exercise the construction's
    /// bookkeeping without pulling in a feature-gated permutation.
    #[derive(Clone, Default)]
    struct Rotate;

    impl Permutation<WIDTH> for Rotate {
        type U = u8;

        fn permute_mut(&self, state: &mut [u8; WIDTH]) {
            *state = core::array::from_fn(|i| state[(i + 1) % WIDTH].wrapping_add(i as u8 + 1));
        }
    }

    type Sponge = DuplexSponge<Rotate, WIDTH, RATE>;

    /// Absorbing the empty string is the identity. It must not restart the
    /// squeeze stream: `squeeze; absorb(&[]); squeeze` has to equal one
    /// contiguous `squeeze`, matching the XOF instantiations.
    #[test]
    fn empty_absorb_is_a_no_op() {
        let mut streaming = Sponge::default();
        streaming.absorb(b"message");
        let (mut lo, mut hi) = ([0u8; 12], [0u8; 12]);
        streaming.squeeze(&mut lo);
        streaming.absorb(&[]);
        streaming.squeeze(&mut hi);

        let mut contiguous = Sponge::default();
        let mut all = [0u8; 24];
        contiguous.absorb(b"message").squeeze(&mut all);

        assert_eq!([lo, hi].concat(), all);

        // A non-empty absorb, by contrast, does end the stream.
        let mut reset = Sponge::default();
        reset.absorb(b"message").squeeze(&mut lo);
        reset.absorb(b"more").squeeze(&mut hi);
        assert_ne!([lo, hi].concat(), all);
    }

    /// Absorbing is associative, including across empty chunks.
    #[test]
    fn absorb_is_associative() {
        let mut split = Sponge::default();
        split.absorb(b"hello ").absorb(&[]).absorb(b"world");
        let mut joined = Sponge::default();
        joined.absorb(b"hello world");
        assert_eq!(split.squeeze_array::<32>(), joined.squeeze_array::<32>());
    }

    /// Squeezing is iterative: one rate block per iteration, not per stack
    /// frame. A recursive implementation overflows well before this size on a
    /// default test-thread stack.
    #[test]
    fn large_squeeze_does_not_recurse() {
        let mut sponge = Sponge::default();
        sponge.absorb(b"message");
        let mut output = alloc::vec![0u8; 1 << 20];
        sponge.squeeze(&mut output);

        // And a chunked squeeze of the same length is byte-identical.
        let mut chunked = Sponge::default();
        chunked.absorb(b"message");
        let mut buf = alloc::vec![0u8; 1 << 20];
        for chunk in buf.chunks_mut(RATE * 3 + 1) {
            chunked.squeeze(chunk);
        }
        assert_eq!(output, buf);
    }
}
