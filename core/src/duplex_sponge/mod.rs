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

#[cfg(feature = "std")]
use std::io::Read;

pub use interface::DuplexSpongeInterface;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ProofError;

mod unit;
pub use unit::Unit;

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

impl<U: Unit, P: Permutation<U = U>> Zeroize for DuplexSponge<P> {
    fn zeroize(&mut self) {
        self.absorb_pos.zeroize();
        self.permutation.as_mut().fill(U::ZERO);
        self.squeeze_pos.zeroize();
    }
}

impl<U: Unit, P: Permutation<U = U>> ZeroizeOnDrop for DuplexSponge<P> {}

impl<U: Unit, P: Permutation<U = U>> DuplexSpongeInterface<U> for DuplexSponge<P> {
    fn new() -> Self {
        assert!(P::R > 0, "The rate segment must be non-trivial");
        assert!(P::N > P::R, "The capacity segment must be non-trivial");

        Self {
            permutation: P::new(),
            absorb_pos: 0,
            squeeze_pos: P::R,
        }
    }

    fn absorb(&mut self, mut input: &[U]) -> &mut Self {
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

    fn squeeze(&mut self, output: &mut [U]) -> &mut Self {
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

    fn pad_block(&mut self) -> &mut Self {
        self.permutation.permute();
        // set to zero the state up to rate
        // XXX. is the compiler really going to do this?
        self.permutation.as_mut()[..P::R].fill(U::ZERO);
        self.squeeze_pos = P::R;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keccak::Keccak;

    #[test]
    fn test_squeeze_zero_after_behavior() {
        let mut sponge = Keccak::new();
        let mut output = [0u8; 64];

        let input = b"Hello, World!";
        sponge.squeeze(&mut [0u8; 0]);
        sponge.absorb(input);
        sponge.squeeze(&mut output);

        assert!(output.iter().any(|u| *u != 0));
    }

    #[test]
    fn test_associativity_of_absorb() {
        let expected_output =
            hex::decode("7dfada182d6191e106ce287c2262a443ce2fb695c7cc5037a46626e88889af58")
                .unwrap();
        let mut sponge1 = Keccak::new();
        sponge1.absorb(b"hello world");
        let mut out1 = [0u8; 32];
        sponge1.squeeze(&mut out1);

        let mut sponge2 = Keccak::new();
        sponge2.absorb(b"hello");
        sponge2.absorb(b" world");
        let mut out2 = [0u8; 32];
        sponge2.squeeze(&mut out2);

        assert_eq!(out1.to_vec(), expected_output);
        assert_eq!(out2.to_vec(), expected_output);
    }

    #[test]
    fn test_tag_affects_output() {
        let mut sponge1 = Keccak::new();
        let mut sponge2 = Keccak::new();

        let mut output1 = [0u8; 32];
        sponge1.absorb(b"input1");
        sponge1.squeeze(&mut output1);

        let mut output2 = [0u8; 32];
        sponge2.absorb(b"input2");
        sponge2.squeeze(&mut output2);

        assert_ne!(output1, output2)
    }

    #[test]
    fn test_zeroize_clears_memory() {
        use core::ptr;

        use zeroize::Zeroize;

        // Create a sponge with sensitive data
        let mut sponge = Keccak::new();
        sponge.absorb(b"secret data that must be cleared");

        // Get a pointer to the internal state before zeroization
        let state_ptr = sponge.permutation.as_ref().as_ptr();
        let state_len = sponge.permutation.as_ref().len();

        // Verify state contains non-zero data
        let has_nonzero_before =
            unsafe { (0..state_len).any(|i| ptr::read(state_ptr.add(i)) != 0) };
        assert!(
            has_nonzero_before,
            "State should contain non-zero data before zeroization"
        );

        sponge.zeroize();

        // Verify all bytes in the state are now zero
        let all_zero_after = unsafe { (0..state_len).all(|i| ptr::read(state_ptr.add(i)) == 0) };
        assert!(
            all_zero_after,
            "State should be completely zeroed after zeroization"
        );

        // Also verify the position counters are zeroed
        assert_eq!(sponge.absorb_pos, 0);
        assert_eq!(sponge.squeeze_pos, 0);
    }
}
