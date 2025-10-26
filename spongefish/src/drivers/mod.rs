//! Bindings to some popular libraries using zero-knowledge.

// Arkworks field implementations
#[cfg(feature = "ark-ff")]
pub mod ark_ff_impl;

// Arkworks elliptic curve implementations
#[cfg(feature = "ark-ec")]
pub mod ark_ec_impl;

// Module for BLS12-381 support
#[cfg(feature = "bls12_381")]
pub mod bls12_381_impl;

// Module for curve25519-dalek support
#[cfg(feature = "curve25519-dalek")]
pub mod curve25519_dalek_impl;

// Module for secp256k1 support (k256)
#[cfg(feature = "k256")]
pub mod secp256k1_impl;

// Plonky3 BabyBear field
#[cfg(feature = "p3-baby-bear")]
pub mod p3_baby_bear;

// Plonky3 Mersenne31 field
#[cfg(feature = "p3-mersenne-31")]
pub mod p3_mersenne31;

// Plonky3 KoalaBear field
#[cfg(feature = "p3-koala-bear")]
pub mod p3_koala_bear;

// Buffer of 512-bytes, useful for decoding 256-bit scalars.
#[repr(C)]
pub struct Array64([u8; 64]);

impl Default for Array64 {
    fn default() -> Self {
        Array64([0u8; 64])
    }
}

impl AsMut<[u8]> for Array64 {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

/// Bytes needed in order to obtain a uniformly distributed random element of `modulus_bits`
#[inline]
#[must_use]
pub const fn bytes_uniform_modp(modulus_bits: u32) -> usize {
    (modulus_bits as usize + 128) / 8
}

/// Bytes needed in order to encode an element of F.
#[inline]
#[must_use]
pub const fn bytes_modp(modulus_bits: u32) -> u64 {
    (modulus_bits as u64).div_ceil(8)
}

// // Integration tests
// #[cfg(test)]
// mod tests;
