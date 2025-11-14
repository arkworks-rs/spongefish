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
impl_integer_unit!(usize);

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
    fn squeeze(&mut self, output: &mut [Self::U]) -> &mut Self;

    /// Ratchet the sponge.
    ///
    /// This function performs a one-way ratchet of its internal state, so that it cannot be inverted.
    /// By default, this function will re-initialize a sponge using 256 [`Unit`]s squeezed from the current instance.
    fn ratchet(&mut self) -> &mut Self;

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

/// A permutation over operating over an array of `WIDTH` [`Unit`]s.
pub trait Permutation<const WIDTH: usize>: Clone {
    /// The [`Unit`] defining the alphabet for the permutation function.
    type U: Unit;

    /// The permutation function.
    fn permute(&self, state: &[Self::U; WIDTH]) -> [Self::U; WIDTH];

    /// In-place permutation function evaluation [`Permutation::permute`].
    fn permute_mut(&self, state: &mut [Self::U; WIDTH]) {
        let new_state = self.permute(state);
        state.clone_from(&new_state);
    }
}

/// The duplex sponge construction from [[CO25], Construction 3.3].
///
/// Based on a [`Permutation`] for `WIDTH` elements, with rate `RATE`.
///
/// # Instantiation
///
/// The rate segment is written in the first units of the sponge;
/// the capacity segment is written in the last `WIDTH`-`RATE` units of the sponge.
///
///
/// # Panics
///
/// Instantiation will panic if `WIDTH` is less or equal to `RATE`, or if `RATE` is zero.
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
        self.permutation_state.as_mut().fill(P::U::ZERO);
        self.squeeze_pos.zeroize();
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

    fn squeeze(&mut self, output: &mut [Self::U]) -> &mut Self {
        if output.is_empty() {
            return self;
        }
        self.absorb_pos = 0;

        if self.squeeze_pos == RATE {
            self.squeeze_pos = 0;
            self.permutation.permute_mut(&mut self.permutation_state);
        }

        debug_assert!(self.squeeze_pos < RATE);
        let chunk_len = usize::min(output.len(), RATE - self.squeeze_pos);
        let (output, rest) = output.split_at_mut(chunk_len);
        output.clone_from_slice(
            &self.permutation_state[self.squeeze_pos..self.squeeze_pos + chunk_len],
        );
        self.squeeze_pos += chunk_len;
        self.squeeze(rest)
    }

    fn ratchet(&mut self) -> &mut Self {
        self.absorb_pos = RATE;
        self.squeeze_pos = RATE;
        self.permutation_state[0..RATE].fill_with(|| P::U::ZERO);
        self.permutation.permute_mut(&mut self.permutation_state);
        self
    }
}
