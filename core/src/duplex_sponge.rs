//! This module defines the duplex sponge construction that can absorb and squeeze data.
//!
//! Hashes in `spongefish` operate over generic elements called [`Unit`].
//! Roughly speaking, a [`Unit`] requires only [`Clone`] and [`Sized`], and has a
//! special element [`Unit::ZERO`] that denotes the default, neutral value to write on initialization and deletion.
//!
//! A [`DuplexSpongeInterface`] is the interface providing basic absorb/squeeze functions over [`Unit`].
//! While it can be built from sponges, [`DuplexSpongeInterface`] is just a trait that can be implemented in different ways. See [`spongefish::instantiations`] for some examples
//! the standard duplex sponge construction in overwrite mode (cf. [Wikipedia](https://en.wikipedia.org/wiki/Sponge_function#Duplex_construction)).
//! - [`legacy::DigestBridge`] takes as input any hash function implementing the NIST API via the standard [`digest::Digest`] trait and makes it suitable for usage in duplex mode for continuous absorb/squeeze.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Basic units over which a sponge operates.
///
/// The only requirement of Units is that they have fixed size, can be copied, and possess a "zero" element.
pub trait Unit: Clone + Sized {
    /// The zero element.
    const ZERO: Self;
}

impl Unit for u8 {
    const ZERO: Self = 0;
}

/// A [`DuplexInterface`] is an abstract interface for absorbing and squeezing data.
/// The type parameter `U` represents basic unit that the sponge works with.
///
/// We require [`DuplexInterface`] implementations to have a [`std::default::Default`] implementation, that initializes
/// to zero the hash function state, and a [`zeroize::Zeroize`] implementation for secure deletion.
///
/// **HAZARD**: Don't implement this trait unless you know what you are doing.
/// Consider using the sponges already provided by this library.
pub trait DuplexSpongeInterface: Clone + zeroize::Zeroize {
    type U: Unit;

    /// Initializes a new sponge, setting up the state.
    fn new() -> Self;

    /// Absorbs new elements in the sponge.
    fn absorb(&mut self, input: &[Self::U]) -> &mut Self;

    /// Squeezes out new elements.
    fn squeeze(&mut self, output: &mut [Self::U]) -> &mut Self;

    /// Ratchet the current block.
    ///
    /// If the underlying hash is processing absorbs in blocks, this function will fill it
    /// so that future absorbs can rely on the full "rate" of the underlying hash.
    fn ratchet(&mut self) -> &mut Self {
        let seed = self.squeeze_array::<256>();
        self.zeroize();
        self.absorb(&seed)
    }

    fn squeeze_array<const LEN: usize>(&mut self) -> [Self::U; LEN] {
        let mut output = [Self::U::ZERO; LEN];
        self.squeeze(&mut output);
        output
    }

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
/// For implementors:
///
/// - State is written in *the first* [`Permutation::R`] (rate) bytes of the state.
/// The last [`Permutation::N`]-[`Permutation::R`] bytes are never touched directly except during initialization.
/// - The duplex sponge is in *overwrite mode*.
/// This mode is not known to affect the security levels and removes assumptions on [`Permutation::U`]
/// as well as constraints in the final zero-knowledge proof implementing the hash function.
/// - The [`std::default::Default`] implementation *MUST* initialize the state to zero.
/// - The [`Permutation::new`] method should initialize the sponge writing the entropy provided in the `iv` in the last [`Permutation::N`]-[`Permutation::R`] elements of the state.
pub trait Permutation: Clone + AsRef<[Self::U]> + AsMut<[Self::U]> {
    /// The basic unit over which the sponge operates.
    type U: Unit;

    /// The width of the sponge, equal to rate [`Permutation::R`] plus capacity.
    /// Cannot be less than 1. Cannot be less than [`Permutation::R`].
    const N: usize;

    /// The rate of the sponge.
    const R: usize;

    /// Initialize a new permutation state
    fn new() -> Self;

    /// Permute the state of the sponge.
    fn permute(&mut self);
}

/// A cryptographic sponge.
#[derive(Clone, PartialEq, Eq)]
pub struct DuplexSponge<P: Permutation> {
    permutation: P,
    absorb_pos: usize,
    squeeze_pos: usize,
}

impl<P: Permutation> Default for DuplexSponge<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Permutation> Zeroize for DuplexSponge<P> {
    fn zeroize(&mut self) {
        self.absorb_pos.zeroize();
        self.permutation.as_mut().fill(P::U::ZERO);
        self.squeeze_pos.zeroize();
    }
}

impl<P: Permutation> ZeroizeOnDrop for DuplexSponge<P> {}

impl<P: Permutation> DuplexSpongeInterface for DuplexSponge<P> {
    type U = P::U;
    fn new() -> Self {
        assert!(P::R > 0, "The rate segment must be non-trivial");
        assert!(P::N > P::R, "The capacity segment must be non-trivial");

        Self {
            permutation: P::new(),
            absorb_pos: 0,
            squeeze_pos: P::R,
        }
    }

    fn absorb(&mut self, mut input: &[Self::U]) -> &mut Self {
        self.squeeze_pos = P::R;

        while !input.is_empty() {
            if self.absorb_pos == P::R {
                self.permutation.permute();
                self.absorb_pos = 0;
            } else {
                assert!(self.absorb_pos < P::R);
                let chunk_len = usize::min(input.len(), P::R - self.absorb_pos);
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

        if self.squeeze_pos == P::R {
            self.squeeze_pos = 0;
            self.permutation.permute();
        }

        assert!(self.squeeze_pos < P::R);
        let chunk_len = usize::min(output.len(), P::R - self.squeeze_pos);
        let (output, rest) = output.split_at_mut(chunk_len);
        output.clone_from_slice(
            &self.permutation.as_ref()[self.squeeze_pos..self.squeeze_pos + chunk_len],
        );
        self.squeeze_pos += chunk_len;
        self.squeeze(rest)
    }

    fn ratchet(&mut self) -> &mut Self {
        self.absorb_pos = P::R;
        self.squeeze_pos = P::R;
        self
    }
}
