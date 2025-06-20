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
        self.squeeze_pos = C::R;

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
        self
    }

    fn squeeze_unchecked(&mut self, output: &mut [U]) -> &mut Self {
        if output.is_empty() {
            return self;
        }
        self.absorb_pos = 0;

        if self.squeeze_pos == C::R {
            self.squeeze_pos = 0;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keccak::Keccak;

    #[test]
    fn test_keccak_duplex_sponge() {
        let mut sponge = Keccak::new(*b"unit_tests_keccak_tag___________");
        let mut output = [0u8; 64];

        let input = b"Hello, World!";
        sponge.absorb_unchecked(input);
        sponge.squeeze_unchecked(&mut output);

        assert_eq!(output.to_vec(), hex::decode("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c").unwrap());
    }

    #[test]
    fn test_absorb_empty_before_does_not_break() {
        let mut sponge = Keccak::new(*b"unit_tests_keccak_tag___________");
        let mut output = [0u8; 64];

        let input = b"Hello, World!";
        sponge.absorb_unchecked(input);
        sponge.absorb_unchecked(b"");
        sponge.squeeze_unchecked(&mut output);

        assert_eq!(output.to_vec(), hex::decode("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c").unwrap());
    }

    #[test]
    fn test_absorb_empty_after_does_not_break() {
        let mut sponge = Keccak::new(*b"unit_tests_keccak_tag___________");
        let mut output = [0u8; 64];

        let input = b"Hello, World!";
        sponge.absorb_unchecked(b"");
        sponge.absorb_unchecked(input);
        sponge.squeeze_unchecked(&mut output);

        assert_eq!(output.to_vec(), hex::decode("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c").unwrap());
    }

    #[test]
    fn test_squeeze_zero_behavior() {
        let mut sponge = Keccak::new(*b"unit_tests_keccak_tag___________");
        let mut output = [0u8; 64];

        let input = b"Hello, World!";
        sponge.squeeze_unchecked(&mut [0u8; 0]);
        sponge.absorb_unchecked(input);
        sponge.squeeze_unchecked(&mut [0u8; 0]);
        sponge.squeeze_unchecked(&mut output);

        assert_eq!(output.to_vec(), hex::decode("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c").unwrap());
    }

    #[test]
    fn test_squeeze_zero_after_behavior() {
        let mut sponge = Keccak::new(*b"unit_tests_keccak_tag___________");
        let mut output = [0u8; 64];

        let input = b"Hello, World!";
        sponge.squeeze_unchecked(&mut [0u8; 0]);
        sponge.absorb_unchecked(input);
        sponge.squeeze_unchecked(&mut output);

        assert_eq!(output.to_vec(), hex::decode("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c").unwrap());
    }

    #[test]
    fn test_absorb_squeeze_absorb_consistency() {
        let mut sponge = Keccak::new(*b"edge-case-test-domain-absorb0000");
        let mut output = [0u8; 32];

        sponge.absorb_unchecked(b"first");
        sponge.squeeze_unchecked(&mut output);
        sponge.absorb_unchecked(b"second");
        sponge.squeeze_unchecked(&mut output);

        assert_eq!(
            output.to_vec(),
            hex::decode("20ce6da64ffc09df8de254222c068358da39d23ec43e522ceaaa1b82b90c8b9a")
                .unwrap()
        );
    }

    #[test]
    fn test_associativity_of_absorb() {
        let expected_output =
            hex::decode("7dfada182d6191e106ce287c2262a443ce2fb695c7cc5037a46626e88889af58")
                .unwrap();
        let tag = *b"absorb-associativity-domain-----";

        let mut sponge1 = Keccak::new(tag);
        sponge1.absorb_unchecked(b"hello world");
        let mut out1 = [0u8; 32];
        sponge1.squeeze_unchecked(&mut out1);

        let mut sponge2 = Keccak::new(tag);
        sponge2.absorb_unchecked(b"hello");
        sponge2.absorb_unchecked(b" world");
        let mut out2 = [0u8; 32];
        sponge2.squeeze_unchecked(&mut out2);

        assert_eq!(out1.to_vec(), expected_output);
        assert_eq!(out2.to_vec(), expected_output);
    }

    #[test]
    fn test_tag_affects_output() {
        let mut sponge1 = Keccak::new(*b"domain-one-differs-here-00000000");
        let mut sponge2 = Keccak::new(*b"domain-two-differs-here-00000000");

        let mut output1 = [0u8; 32];
        sponge1.absorb_unchecked(b"input");
        sponge1.squeeze_unchecked(&mut output1);

        let mut output2 = [0u8; 32];
        sponge2.absorb_unchecked(b"input");
        sponge2.squeeze_unchecked(&mut output2);

        assert_eq!(
            output1.to_vec(),
            hex::decode("2ecad63584ec0ff7f31edb822530762e5cb4b7dc1a62b1ffe02c43f3073a61b8")
                .unwrap()
        );
        assert_eq!(
            output2.to_vec(),
            hex::decode("6310fa0356e1bab0442fa19958e1c4a6d1dcc565b2b139b6044d1a809f531825")
                .unwrap()
        );
    }

    #[test]
    fn test_multiple_blocks_absorb_squeeze() {
        let mut sponge = Keccak::new(*b"multi-block-absorb-test_________");
        let input = vec![0xABu8; 3 * 200];
        let mut output = vec![0u8; 3 * 200];

        sponge.absorb_unchecked(&input);
        sponge.squeeze_unchecked(&mut output);

        assert_eq!(output, hex::decode("606310f839e763f4f37ce4c9730da92d4d293109de06abee8a7b40577125bcbfca331b97aee104d03139247e801d8b1a5f6b028b8e51fd643de790416819780a1235357db153462f78c150e34f29a303288f07f854e229aed41c786313119a1cee87402006ab5102271576542e5580be1927af773b0f1b46ce5c78c15267d3729928909192ea0115fcb9475b38a1ff5004477bbbb1b1f5c6a5c90c29b245a83324cb108133efc82216d33da9866051d93baab3bdf0fe02b007d4eb94885a42fcd02a9acdd47b71b6eeac17f5946367d6c69c95cbb80ac91d75e22c9862cf5fe10c7e121368e8a8cd9ff8eebe21071ff014e053725bcc624cd9f31818c4d049e70c14a22e5d3062a553ceca6157315ef2bdb3619c970c9c3d60817ee68291dcd17a282ed1b33cb3afb79c8247cd46de13add88da4418278c8b6b919914be5379daa823b036da008718c1d2a4a0768ecdf032e2b93c344ff65768c8a383a8747a1dcc13b5569b4e15cab9cc8f233fb28b13168284c8a998be6f8fa05389ff9c1d90c5845060d2df3fe0a923be8603abbd2b6f6dd6a5c09c81afe7c06bec789db87185297d6f7261f1e5637f2d140ff3b306df77f42cceffe769545ea8b011022387cd9e3d4f2c97feff5099139715f72301799fcfd59aa30f997e26da9eb7d86ee934a3f9c116d4a9e1012d795db35e1c61d27cd74bb6002f463fc129c1f9c4f25bc8e79c051ac2f1686e393d670f8d1e4cea12acfbff5a135623615d69a88f390569f17a0fc65f5886e2df491615155d5c3eb871209a5c7b0439585ad1a0acbede2e1a8d5aad1d8f3a033267e12185c5f2bbab0f2f1769247").unwrap());
    }
}
