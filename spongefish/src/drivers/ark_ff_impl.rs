//! Helpers for bridging `ark_ff` field types with `spongefish` codecs.
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use ark_ff::{BigInteger, Field, Fp, FpConfig, PrimeField};

use crate::{
    codecs::{Decoding, Encoding},
    error::VerificationError,
    io::NargDeserialize,
    VerificationResult,
};

// Make arkworks field elements a valid Unit type
impl<C: ark_ff::FpConfig<N>, const N: usize> crate::Unit for Fp<C, N> {
    const ZERO: Self = C::ZERO;
}

/// A buffer meant to hold enough bytes for obtaining a uniformly-distributed
/// random field element.
/// In practice, for [`DecodingFieldBuffer`] is meant to hold `F::MODULUS_BIT_SIZE.div_ceil(8) + 32`
/// bytes. Unfortunately Rust does not support const generic expressions,
/// and so [`DecodingFieldBuffer`] is implemented as a vector of [`u8`] with a [`PhantomData`]
/// marker binding it to the [`ark_ff::Field`].
pub struct DecodingFieldBuffer<F: Field> {
    buf: Vec<u8>,
    _phantom: PhantomData<F>,
}

/// The function determining the size of [`DecodingFieldBuffer`]:
pub fn decoding_field_buffer_size<F: Field>() -> usize {
    let base_field_modulus_bytes = F::BasePrimeField::MODULUS_BIT_SIZE.div_ceil(8) as u64;
    // Get 32 bytes of extra randomness for every base field element in the extension
    let length = (base_field_modulus_bytes + 32) * F::extension_degree();
    length as usize
}

/// A macro to bridge [`ark_serialize::CanonicalDeserialize`] with [`NargDeserialize`].
///
/// arkworks implements deserialization exactly as we want for field and elliptic curve elements.
/// However, when used on slices, vectors, or fixed-length arrays it will also try to read the array length
/// in the first 8 bytes.
/// We work around that implementing [`NargDeserialize`] for it ourselves.
macro_rules! impl_deserialize {
    (impl [$($generics:tt)*] for $type:ty) => {
        impl<$($generics)*> NargDeserialize for $type {
            fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
                let extension_degree = <Self as Field>::extension_degree() as usize;
                let base_field_size = (<Self as Field>::BasePrimeField::MODULUS_BIT_SIZE
                    .div_ceil(8)) as usize;
                let total_bytes = extension_degree * base_field_size;
                if buf.len() < total_bytes {
                    return Err(VerificationError);
                }
                let (head, tail) = buf.split_at(total_bytes);
                *buf = tail;

                let mut base_elems = Vec::with_capacity(extension_degree);
                for chunk in head.chunks_exact(base_field_size) {
                    let elem = <<Self as Field>::BasePrimeField as PrimeField>::from_le_bytes_mod_order(chunk);
                    base_elems.push(elem);
                }
                debug_assert_eq!(base_elems.len(), extension_degree);
                Self::from_base_prime_field_elems(base_elems).ok_or(VerificationError)
            }
        }
    };
}

/// A macro to bridge [`ark_serialize::CanonicalSerialize`] with [`Encoding`].
///
/// arkworks implements serialization exactly as we want for field and elliptic curve elements.
/// However, when used over slices, vectors, or fixed-length arrays it will also write the array length
/// in the first 8 bytes.
/// We work around that implementing [NargSerialize][`spongefish::NargSerialize`] for those types ourselves.
macro_rules! impl_encoding {
    (impl [$($generics:tt)*] for $type:ty) => {
        impl<$($generics)*> Encoding<[u8]> for $type {
            fn encode(&self) -> impl AsRef<[u8]> {
                let base_field_size = (<Self as Field>::BasePrimeField::MODULUS_BIT_SIZE
                    .div_ceil(8)) as usize;
                let mut buf = Vec::with_capacity(base_field_size * <Self as Field>::extension_degree() as usize);
                for base_element in self.to_base_prime_field_elements() {
                    let mut bytes = base_element.into_bigint().to_bytes_le();
                    bytes.resize(base_field_size, 0);
                    buf.extend_from_slice(&bytes);
                }
                buf
            }
        }
    };
}

/// Macro to implement [`Decoding`] for some [`ark_ff::Field`] instantiations.
///
/// Remember that the Rust type system does not accept conflicting blanket implementations,
/// so we can't implement [`Decoding`] for `ark_ff::Field` and `ark_ff::AdditiveGroup`: the compiler
/// will complain that a type might be implementing both in the future.
macro_rules! impl_decoding {
        (impl [$($generics:tt)*] for $type:ty) => {
        impl<$($generics)*> Decoding<[u8]> for $type {
            type Repr = DecodingFieldBuffer<$type>;

            fn decode(repr: Self::Repr) -> Self {
                debug_assert_eq!(repr.buf.len(), decoding_field_buffer_size::<Self>());
                let base_field_size = decoding_field_buffer_size::<<Self as Field>::BasePrimeField>();

                let result = repr.buf.chunks(base_field_size)
                    .map(|chunk| <Self as Field>::BasePrimeField::from_le_bytes_mod_order(chunk))
                    .collect::<Vec<_>>();
                // Convert Vec to array - this unwrap is safe because we know the length
                Self::from_base_prime_field_elems(result).unwrap()
            }
        }
    }
}

// Implement NargDeserialize for prime-order fields and field extensions.
impl_deserialize!(impl [C: FpConfig<N>, const N: usize] for Fp<C, N>);
impl_deserialize!(impl [C: ark_ff::Fp2Config] for ark_ff::Fp2<C>);
impl_deserialize!(impl [C: ark_ff::Fp3Config] for ark_ff::Fp3<C>);
impl_deserialize!(impl [C: ark_ff::Fp4Config] for ark_ff::Fp4<C>);
impl_deserialize!(impl [C: ark_ff::Fp6Config] for ark_ff::Fp6<C>);
impl_deserialize!(impl [C: ark_ff::Fp12Config] for ark_ff::Fp12<C>);
// Implement Encoding for prime-order field and field extensions.
// The NargSerialize implementation is inherited here.
impl_encoding!(impl [C: FpConfig<N>, const N: usize] for Fp<C, N>);
impl_encoding!(impl [C: ark_ff::Fp2Config] for ark_ff::Fp2<C>);
impl_encoding!(impl [C: ark_ff::Fp3Config] for ark_ff::Fp3<C>);
impl_encoding!(impl [C: ark_ff::Fp4Config] for ark_ff::Fp4<C>);
impl_encoding!(impl [C: ark_ff::Fp6Config] for ark_ff::Fp6<C>);
impl_encoding!(impl [C: ark_ff::Fp12Config] for ark_ff::Fp12<C>);
// Implement Decoding for prime-order fields and field extensions.
impl_decoding!(impl [C: FpConfig<N>, const N: usize] for Fp<C, N>);
impl_decoding!(impl [C: ark_ff::Fp2Config] for ark_ff::Fp2<C>);
impl_decoding!(impl [C: ark_ff::Fp3Config] for ark_ff::Fp3<C>);
impl_decoding!(impl [C: ark_ff::Fp4Config] for ark_ff::Fp4<C>);
impl_decoding!(impl [C: ark_ff::Fp6Config] for ark_ff::Fp6<C>);
impl_decoding!(impl [C: ark_ff::Fp12Config] for ark_ff::Fp12<C>);

/// Number of uniformly random bits in a uniformly-distributed element in `[0, b)`
///
/// This function returns the maximum n for which
/// `Uniform([b]) mod 2^n`
/// and
/// `Uniform([2^n])`
/// are statistically indistinguishable.
/// Given \(b = q 2^n + r\) the statistical distance
/// is \(\frac{2r}{ab}(a-r)\).
#[allow(unused)]
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

impl<F: Field> Default for DecodingFieldBuffer<F> {
    fn default() -> Self {
        let base_field_modulus_bytes = F::BasePrimeField::MODULUS_BIT_SIZE.div_ceil(8) as u64;
        // Get 32 bytes of extra randomness for every base field element in the extension
        let len = (base_field_modulus_bytes + 32) * F::extension_degree();
        Self {
            buf: vec![0u8; len as usize],
            _phantom: PhantomData,
        }
    }
}

impl<F: Field> AsMut<[u8]> for DecodingFieldBuffer<F> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut()
    }
}
