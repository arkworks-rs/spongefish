use alloc::{vec, vec::Vec};
use core::mem::size_of;

use ark_ff::{BigInteger, Fp, FpConfig, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    codecs::{Decoding, Encoding},
    drivers::bytes_uniform_modp,
    error::VerificationError,
    io::Deserialize,
    VerificationResult,
};

// Make arkworks field elements a valid Unit type
impl<C: ark_ff::FpConfig<N>, const N: usize> crate::Unit for Fp<C, N> {
    const ZERO: Self = C::ZERO;
}

// Buffer for decoding field elements
pub struct ScalarBuffer<const N: usize>(Vec<u8>);

impl<const N: usize> Default for ScalarBuffer<N> {
    fn default() -> Self {
        let len = size_of::<u64>() * N + 32;
        ScalarBuffer(vec![0u8; len])
    }
}

impl<const N: usize> AsMut<[u8]> for ScalarBuffer<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

// Implement Decoding for arkworks field elements
impl<const N: usize, C: FpConfig<N>> Decoding<[u8]> for ark_ff::Fp<C, N> {
    type Repr = ScalarBuffer<N>;

    fn decode(buf: <Self as Decoding<[u8]>>::Repr) -> Self {
        Self::from_le_bytes_mod_order(&buf.0)
    }
}

// Use the macro to implement Deserialize for various arkworks fields
macro_rules! impl_deserialize {
    (impl [$($generics:tt)*] for $type:ty) => {
        impl<$($generics)*> Deserialize for $type {
            fn deserialize_from(buf: &mut &[u8]) -> VerificationResult<Self> {
                let bytes_len: usize = Self::default().compressed_size();
                if buf.len() < bytes_len {
                    return Err(VerificationError);
                }
                let (head, tail) = buf.split_at(bytes_len);
                *buf = tail;
                Self::deserialize_compressed(head).map_err(|_| VerificationError)
            }
        }
    };
}

impl_deserialize!(impl [C: FpConfig<N>, const N: usize] for Fp<C, N>);
impl_deserialize!(impl [C: ark_ff::Fp2Config] for ark_ff::Fp2<C>);
impl_deserialize!(impl [C: ark_ff::Fp3Config] for ark_ff::Fp3<C>);
impl_deserialize!(impl [C: ark_ff::Fp4Config] for ark_ff::Fp4<C>);
impl_deserialize!(impl [C: ark_ff::Fp6Config] for ark_ff::Fp6<C>);
impl_deserialize!(impl [C: ark_ff::Fp12Config] for ark_ff::Fp12<C>);

// implement Encoding for various arkworks field types
macro_rules! impl_encoding {
    (impl [$($generics:tt)*] for $type:ty) => {
        impl<$($generics)*> Encoding<[u8]> for $type {
            fn encode(&self) -> impl AsRef<[u8]> {
                let mut buf = Vec::new();
                let _ = CanonicalSerialize::serialize_compressed(self, &mut buf);
                buf
            }
        }
    };
}

// Implement Decoding for arrays of prime fields (Fp)
impl<C: FpConfig<N>, const N: usize, const LEN: usize> Decoding<[u8]> for [Fp<C, N>; LEN] {
    type Repr = Vec<u8>;

    fn decode(buf: Self::Repr) -> Self {
        // Calculate how many bytes we have per element
        let bytes_per_elem = buf.len() / LEN;

        // Create array by decoding each chunk
        let mut result = Vec::with_capacity(LEN);
        for i in 0..LEN {
            let start = i * bytes_per_elem;
            let end = (i + 1) * bytes_per_elem;
            let elem = Fp::<C, N>::from_le_bytes_mod_order(&buf[start..end]);
            result.push(elem);
        }

        // Convert Vec to array - this unwrap is safe because we know the length
        result.try_into().unwrap_or_else(|_| unreachable!())
    }
}

impl_encoding!(impl [C: FpConfig<N>, const N: usize] for Fp<C, N>);
impl_encoding!(impl [C: ark_ff::Fp2Config] for ark_ff::Fp2<C>);
impl_encoding!(impl [C: ark_ff::Fp3Config] for ark_ff::Fp3<C>);
impl_encoding!(impl [C: ark_ff::Fp4Config] for ark_ff::Fp4<C>);
impl_encoding!(impl [C: ark_ff::Fp6Config] for ark_ff::Fp6<C>);
impl_encoding!(impl [C: ark_ff::Fp12Config] for ark_ff::Fp12<C>);

// Helper function to convert bytes to field elements
pub fn from_random_bytes<C: FpConfig<N>, const N: usize>(bytes: &[u8]) -> Vec<Fp<C, N>> {
    let base_field_size = bytes_uniform_modp(Fp::<C, N>::MODULUS_BIT_SIZE);
    bytes
        .chunks(base_field_size)
        .map(|chunk| Fp::<C, N>::from_be_bytes_mod_order(chunk))
        .collect()
}

// Helper function to get uniformly random bytes from a field element
pub fn to_random_bytes<C: FpConfig<N>, const N: usize>(field_elem: &Fp<C, N>) -> Vec<u8> {
    let bytes = field_elem.into_bigint().to_bytes_le();
    let useful_bytes = random_bytes_in_random_modp::<N>(Fp::<C, N>::MODULUS);
    bytes[..useful_bytes].to_vec()
}

/// Number of uniformly random bytes in a uniformly-distributed element in `[0, b)`
fn random_bytes_in_random_modp<const N: usize>(modulus: ark_ff::BigInt<N>) -> usize {
    random_bits_in_random_modp(modulus) / 8
}

/// Number of uniformly random bits in a uniformly-distributed element in `[0, b)`
///
/// This function returns the maximum n for which
/// `Uniform([b]) mod 2^n`
/// and
/// `Uniform([2^n])`
/// are statistically indistinguishable.
/// Given \(b = q 2^n + r\) the statistical distance
/// is \(\frac{2r}{ab}(a-r)\).
fn random_bits_in_random_modp<const N: usize>(b: ark_ff::BigInt<N>) -> usize {
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

#[cfg(test)]
mod test_ark_ff {
    use crate::codecs::Encoding;

    fn encoding_testsuite<F: ark_ff::Field + Encoding<[u8]>>() {
        let first = F::from(10);
        let second = F::from(20);
        let first_encoding = Encoding::<[u8]>::encode(&first);
        let second_encoding = Encoding::<[u8]>::encode(&second);
        assert_ne!(first_encoding.as_ref(), second_encoding.as_ref());

        let first = F::from(10);
        let second = -F::from(10) + F::from(20);
        assert_eq!(
            Encoding::encode(&first).as_ref(),
            Encoding::encode(&second).as_ref()
        );
        assert_eq!(
            Encoding::encode(&[first, second]).as_ref(),
            Encoding::encode(&[second, first]).as_ref()
        )
    }

    #[test]
    fn test_encoding() {
        encoding_testsuite::<ark_bls12_381::Fr>();
        encoding_testsuite::<ark_bls12_381::Fq>();
        encoding_testsuite::<ark_bls12_381::Fq2>();
        encoding_testsuite::<ark_bls12_381::Fq12>();
    }
}
