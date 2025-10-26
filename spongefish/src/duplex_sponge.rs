//! This module defines the duplex sponge construction that can absorb and squeeze data.
//!
//! Hashes can operate over generic elements called [`Unit`], be them field elements, bytes, or any other data structure.
//! Roughly speaking, a [`Unit`] requires only [`Clone`] and [`Sized`], and has a
//! special element [`Unit::ZERO`] that denotes the default, neutral value to write on initialization and deletion.
//!
//! A [`DuplexSpongeInterface`] is the interface providing basic absorb/squeeze functions over [`Unit`]s.
//! On top of which we build the prover and verifier state.
//!
//! Many instantiations of [`DuplexSpongeInterface`] are provided in this crate.
//! While a formal analysis exists only for ideal permutations using [`Permutation`] used with the [`DuplexSponge`] struct,
//! we also provide additional examples from generic XOFs implementing [`digest::ExtendableOutput`] and hash functions implementing [`digest::Digest`].

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A trait denoting the requirements for the elements of the sponge alphabet.
pub trait Unit: Clone + Sized {
    /// The zero element.
    const ZERO: Self;
}

impl Unit for u8 {
    const ZERO: Self = 0;
}

/// A [`DuplexSpongeInterface`] is an abstract interface for absorbing and squeezing elements implementing [`Unit`].
///
/// **HAZARD**: Don't implement this trait unless you know what you are doing.
/// Consider using the sponges already provided by this library.
pub trait DuplexSpongeInterface: Clone {
    type U: Unit;

    /// Initialize the state of the duplex sponge.
    fn new() -> Self;

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
    fn squeeze(&mut self, output: &mut [Self::U]) -> &mut Self;

    /// Ratchet the sponge.
    ///
    /// This function performs a one-way ratchet of its internal state, so that it cannot be inverted.
    /// By default, this function will re-initialize a sponge using 256 [`Unit`]s squeezed from the current instance.
    fn ratchet(&mut self) -> &mut Self {
        let seed = self.squeeze_array::<256>();
        // Reset to new state - implementations should overwrite their internal state
        *self = Self::new();
        self.absorb(&seed)
    }

    /// Squeeze a fixed-length array of size `LEN`.
    fn squeeze_array<const LEN: usize>(&mut self) -> [Self::U; LEN] {
        let mut output = [Self::U::ZERO; LEN];
        self.squeeze(&mut output);
        output
    }

    /// Squeeze `len` elements into a fresh-allocated array.
    fn squeeze_boxed(&mut self, len: usize) -> alloc::boxed::Box<[Self::U]> {
        let mut output = alloc::vec![Self::U::ZERO; len];
        self.squeeze(&mut output);
        output.into_boxed_slice()
    }
}

/// The basic state of a cryptographic sponge.
///
/// A cryptographic sponge operates over some domain [`Permutation::U`] units.
/// It has a width [`Permutation::N`] and can process elements at rate [`Permutation::R`],
/// using the permutation function [`Permutation::permute`].
///
///
/// The permutation state can be initialized via [`new`][Permutation::new], accessed via [`as_ref`][AsRef] and altered via [`as_mut`][AsMut].
/// The constant [`WIDTH`] denotes the size of the permutation.
pub trait Permutation: Clone + AsRef<[Self::U]> + AsMut<[Self::U]> {
    /// The basic unit type over which the sponge operates.
    type U: Unit;
    const WIDTH: usize;

    /// Initialize a new permutation state
    fn new() -> Self;

    /// Permute the state of the sponge.
    fn permute(&mut self);
}

/// The duplex sponge construction from [[CO25], Construction 3.3].
///
/// Based on a [`Permutation`] and a [`usize`] constant [`RATE`] defining the rate.
/// The rate segment of the [DuplexSponge] is written in the first
/// [`as_mut()`][`Permutation::as_mut`] units of the sponge.
/// The capacity segment is written in the last [`Permutation::WIDTH`]-[`RATE`] units of the sponge.
///
///
/// # Safety
///
/// Instantiation will fail if [`Permutation::WIDTH`] is less or equal to [`RATE`], or if [`RATE`] is zero.
///
/// [CO25]: https://eprint.iacr.org/2025/536.pdf
#[derive(Clone, PartialEq, Eq)]
pub struct DuplexSponge<P: Permutation, const RATE: usize> {
    permutation: P,
    absorb_pos: usize,
    squeeze_pos: usize,
}

impl<P: Permutation, const RATE: usize> Default for DuplexSponge<P, RATE> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "zeroize")]
impl<P: Permutation, const RATE: usize> Zeroize for DuplexSponge<P, RATE> {
    fn zeroize(&mut self) {
        self.absorb_pos.zeroize();
        self.permutation.as_mut().fill(P::U::ZERO);
        self.squeeze_pos.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P: Permutation, const RATE: usize> ZeroizeOnDrop for DuplexSponge<P, RATE> {}

impl<P: Permutation, const RATE: usize> DuplexSpongeInterface for DuplexSponge<P, RATE> {
    type U = P::U;
    fn new() -> Self {
        assert!(RATE > 0, "The rate must be non-zero");
        assert!(P::WIDTH > RATE, "The capacity must be non-zero");

        Self {
            permutation: P::new(),
            absorb_pos: 0,
            squeeze_pos: RATE,
        }
    }

    fn absorb(&mut self, mut input: &[Self::U]) -> &mut Self {
        self.squeeze_pos = RATE;

        while !input.is_empty() {
            if self.absorb_pos == RATE {
                self.permutation.permute();
                self.absorb_pos = 0;
            } else {
                assert!(self.absorb_pos < RATE);
                let chunk_len = usize::min(input.len(), RATE - self.absorb_pos);
                let (chunk, rest) = input.split_at(chunk_len);

                self.permutation.as_mut()[self.absorb_pos..self.absorb_pos + chunk_len]
                    .clone_from_slice(chunk);
                self.absorb_pos += chunk_len;
                input = rest;
            }
        }
        self
    }

    fn squeeze(&mut self, output: &mut [Self::U]) -> &mut Self {
        if output.is_empty() {
            return self;
        }
        self.absorb_pos = 0;

        if self.squeeze_pos == RATE {
            self.squeeze_pos = 0;
            self.permutation.permute();
        }

        assert!(self.squeeze_pos < RATE);
        let chunk_len = usize::min(output.len(), RATE - self.squeeze_pos);
        let (output, rest) = output.split_at_mut(chunk_len);
        output.clone_from_slice(
            &self.permutation.as_ref()[self.squeeze_pos..self.squeeze_pos + chunk_len],
        );
        self.squeeze_pos += chunk_len;
        self.squeeze(rest)
    }

    fn ratchet(&mut self) -> &mut Self {
        self.absorb_pos = RATE;
        self.squeeze_pos = RATE;
        self
    }
}
