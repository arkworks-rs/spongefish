//!  Bindings to some popular libraries using zero-knowledge.

/// Extension traits macros, for both arkworks and group.
#[cfg(any(feature = "arkworks-algebra", feature = "zkcrypto-group"))]
mod traits;

pub mod arkworks;
mod bytes;
mod zerocopy;

pub use self::{
    bytes::{BytesPattern, BytesProver, BytesVerifier},
    zerocopy::{
        ZeroCopyHintPattern, ZeroCopyHintProver, ZeroCopyHintVerifier, ZeroCopyPattern,
        ZeroCopyProver, ZeroCopyVerifier,
    },
};

//#[cfg(feature = "arkworks-algebra")]
/// Arkworks's [algebra](https://github.com/arkworks-rs/algebra) bindings.
// pub mod arkworks_algebra;

#[cfg(feature = "zkcrypto-group")]
/// (In-progress) [group](https://github.com/zkcrypto/group) bindings.
/// This plugin is experimental and has not yet been thoroughly tested.
pub mod zkcrypto_group;

#[cfg(feature = "ark-serialize")]
/// Use [`ark_serialize`] to convert types to/from bytes.
pub mod zerocopy;

// #[cfg(feature = "serde-postcard")]
// /// Use [`zerocopy`] to convert types to/from bytes.
// pub mod zerocopy;

/// Bytes needed in order to obtain a uniformly distributed random element of `modulus_bits`
pub(super) const fn bytes_uniform_modp(modulus_bits: u32) -> usize {
    (modulus_bits as usize + 128) / 8
}

/// Number of uniformly random bytes of in a uniformly-distributed element in `[0, b)`.
///
/// This function returns the maximum n for which
/// `Uniform([b]) mod 2^n`
/// and
/// `Uniform([2^n])`
/// are statistically indistinguishable.
/// Given \(b = q 2^n + r\) the statistical distance
/// is \(\frac{2r}{ab}(a-r)\).
#[cfg(feature = "arkworks-algebra")]
pub(super) fn random_bits_in_random_modp<const N: usize>(b: ark_ff::BigInt<N>) -> usize {
    use ark_ff::{BigInt, BigInteger};
    // XXX. is it correct to have num_bits+1 here?
    for n in (0..=b.num_bits()).rev() {
        // compute the remainder of b by 2^n
        let r_bits = &b.to_bits_le()[..n as usize];
        let r = BigInt::<N>::from_bits_le(r_bits);
        let log2_a_minus_r = r_bits.iter().rev().skip_while(|&&bit| bit).count() as u32;
        if b.num_bits() + n - 1 - r.num_bits() - log2_a_minus_r >= 128 {
            return n as usize;
        }
    }
    0
}

/// Same as above, but for bytes
#[cfg(feature = "arkworks-algebra")]
pub(super) fn random_bytes_in_random_modp<const N: usize>(modulus: ark_ff::BigInt<N>) -> usize {
    random_bits_in_random_modp(modulus) / 8
}

/// Bytes needed in order to encode an element of F.
pub(super) const fn bytes_modp(modulus_bits: u32) -> usize {
    (modulus_bits as usize).div_ceil(8)
}

/// Unit-tests for inter-operability among libraries.
#[cfg(all(test, feature = "arkworks-algebra", feature = "zkcrypto-group"))]
mod tests;
