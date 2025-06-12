//! This module defines the duplex sponge construction that can absorb and squeeze data.
//! Hashes in `spongefish` operate over some native elements satisfying the trait [`Unit`] which, roughly speaking, requires
//! the basic type to support cloning, size, read/write procedures, and secure deletion.
//!
//! Additionally, the module exports some utilities:
//! - [`DuplexSponge`] allows to implement a [`DuplexInterface`] using a secure permutation function, specifying the rate `R` and the width `N`.
//! This is done using the standard duplex sponge construction in overwrite mode (cf. [Wikipedia](https://en.wikipedia.org/wiki/Sponge_function#Duplex_construction)).
//! - [`legacy::DigestBridge`] takes as input any hash function implementing the NIST API via the standard [`digest::Digest`] trait and makes it suitable for usage in duplex mode for continuous absorb/squeeze.

/// Sponge functions.
mod interface;
/// Legacy hash functions support (e.g. [`sha2`](https://crates.io/crates/sha2), [`blake2`](https://crates.io/crates/blake2)).
pub mod legacy;

pub use interface::DuplexSpongeInterface;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Basic units over which a sponge operates.
///
/// We require the units to have a precise size in memory, to be cloneable,
/// and that we can zeroize them.
pub trait Unit: Clone + Sized + zeroize::Zeroize {
    /// Write a bunch of units in the wire.
    fn write(bunch: &[Self], w: &mut impl std::io::Write) -> Result<(), std::io::Error>;
    /// Read a bunch of units from the wire
    fn read(r: &mut impl std::io::Read, bunch: &mut [Self]) -> Result<(), std::io::Error>;
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
pub trait Permutation: Zeroize + Default + Clone + AsRef<[Self::U]> + AsMut<[Self::U]> {
    /// The basic unit over which the sponge operates.
    type U: Unit;

    /// The width of the sponge, equal to rate [`Permutation::R`] plus capacity.
    /// Cannot be less than 1. Cannot be less than [`Permutation::R`].
    const N: usize;

    /// The rate of the sponge.
    const R: usize;

    /// Initialize the state of the sponge using 32 bytes of seed.
    fn new(iv: [u8; 32]) -> Self;

    /// Permute the state of the sponge.
    fn permute(&mut self);
}

/// A cryptographic sponge.
#[derive(Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct DuplexSponge<C: Permutation> {
    permutation: C,
    absorb_pos: usize,
    squeeze_pos: usize,
}

impl<U: Unit, C: Permutation<U = U>> DuplexSpongeInterface<U> for DuplexSponge<C> {
    fn new(iv: [u8; 32]) -> Self {
        assert!(C::N > C::R, "Capacity of the sponge should be > 0.");
        Self {
            permutation: C::new(iv),
            absorb_pos: 0,
            squeeze_pos: C::R,
        }
    }

    fn absorb_unchecked(&mut self, mut input: &[U]) -> &mut Self {
        while !input.is_empty() {
            if self.absorb_pos == C::R {
                self.permutation.permute();
                self.absorb_pos = 0;
            } else {
                assert!(self.absorb_pos < C::R);
                let chunk_len = usize::min(input.len(), C::R - self.absorb_pos);
                let (chunk, rest) = input.split_at(chunk_len);

                self.permutation.as_mut()[self.absorb_pos..self.absorb_pos + chunk_len]
                    .clone_from_slice(chunk);
                self.absorb_pos += chunk_len;
                input = rest;
            }
        }
        self.squeeze_pos = C::R;
        self
    }

    fn squeeze_unchecked(&mut self, output: &mut [U]) -> &mut Self {
        if output.is_empty() {
            return self;
        }

        if self.squeeze_pos == C::R {
            self.squeeze_pos = 0;
            self.absorb_pos = 0;
            self.permutation.permute();
        }

        assert!(self.squeeze_pos < C::R);
        let chunk_len = usize::min(output.len(), C::R - self.squeeze_pos);
        let (output, rest) = output.split_at_mut(chunk_len);
        output.clone_from_slice(
            &self.permutation.as_ref()[self.squeeze_pos..self.squeeze_pos + chunk_len],
        );
        self.squeeze_pos += chunk_len;
        self.squeeze_unchecked(rest)
    }

    // fn tag(self) -> &'static [Self::U] {
    //     &self.state[C::RATE..]
    // }

    fn ratchet_unchecked(&mut self) -> &mut Self {
        self.permutation.permute();
        // set to zero the state up to rate
        // XXX. is the compiler really going to do this?
        self.permutation.as_mut()[..C::R]
            .iter_mut()
            .for_each(Zeroize::zeroize);
        self.squeeze_pos = C::R;
        self
    }
}
