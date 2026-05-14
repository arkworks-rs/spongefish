//! `ark_ff` bindings: sponge `Unit` impls plus codecs for prime-order fields and extensions.

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use ark_ff::{BigInteger, Field, Fp, FpConfig, PrimeField, SmallFp, SmallFpConfig};

use crate::{Decoding, Encoding, NargDeserialize, VerificationError, VerificationResult};

// Make arkworks field elements a valid Unit type
impl<C: FpConfig<N>, const N: usize> crate::Unit for Fp<C, N> {
    const ZERO: Self = C::ZERO;
}

// Make SmallFp field elements a valid Unit type
impl<P: SmallFpConfig> crate::Unit for SmallFp<P> {
    const ZERO: Self = P::ZERO;
}

fn parse_canonical_prime_field<F: PrimeField>(bytes: &[u8]) -> Option<F> {
    let bits = bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1 == 1))
        .collect::<Vec<_>>();
    let bigint = F::BigInt::from_bits_be(&bits);
    F::from_bigint(bigint)
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
    let base_field_modulus_bytes = u64::from(F::BasePrimeField::MODULUS_BIT_SIZE.div_ceil(8));
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

                let mut base_elems = Vec::with_capacity(extension_degree);
                for chunk in buf[..total_bytes].chunks_exact(base_field_size) {
                    let elem =
                        parse_canonical_prime_field::<<Self as Field>::BasePrimeField>(chunk)
                            .ok_or(VerificationError)?;
                    base_elems.push(elem);
                }
                debug_assert_eq!(base_elems.len(), extension_degree);
                let value = Self::from_base_prime_field_elems(base_elems).ok_or(VerificationError)?;
                *buf = &buf[total_bytes..];
                Ok(value)
            }
        }
    };
}

/// A macro to bridge [`ark_serialize::CanonicalSerialize`] with [`Encoding`].
///
/// arkworks implements serialization exactly as we want for field and elliptic curve elements.
/// However, when used over slices, vectors, or fixed-length arrays it will also write the array length
/// in the first 8 bytes.
/// We work around that by implementing [`Encoding`] for those types ourselves.
macro_rules! impl_encoding {
    (impl [$($generics:tt)*] for $type:ty) => {
        impl<$($generics)*> Encoding<[u8]> for $type {
            fn encode(&self) -> impl AsRef<[u8]> {
                let base_field_size = (<Self as Field>::BasePrimeField::MODULUS_BIT_SIZE
                    .div_ceil(8)) as usize;
                let mut buf = Vec::with_capacity(base_field_size * <Self as Field>::extension_degree() as usize);
                for base_element in self.to_base_prime_field_elements() {
                    let bytes = base_element.into_bigint().to_bytes_be();
                    // Handle BigInt wider than the field (e.g. F16 inside SmallFp's BigInt<1>).
                    let start = bytes.len().saturating_sub(base_field_size);
                    // Handle BigInt narrower than the field (defensive).
                    let padding = base_field_size.saturating_sub(bytes.len());
                    buf.extend(core::iter::repeat_n(0, padding));
                    buf.extend_from_slice(&bytes[start..]);
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
            type Repr = DecodingFieldBuffer<Self>;

            fn decode(repr: Self::Repr) -> Self {
                debug_assert_eq!(repr.buf.len(), decoding_field_buffer_size::<Self>());
                let base_field_size = decoding_field_buffer_size::<<Self as Field>::BasePrimeField>();

                let result = repr.buf.chunks(base_field_size)
                    .map(|chunk| <Self as Field>::BasePrimeField::from_be_bytes_mod_order(chunk))
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
impl_deserialize!(impl [P: SmallFpConfig] for SmallFp<P>);
// Implement Encoding for prime-order field and field extensions.
// The NargSerialize implementation is inherited here.
impl_encoding!(impl [C: FpConfig<N>, const N: usize] for Fp<C, N>);
impl_encoding!(impl [C: ark_ff::Fp2Config] for ark_ff::Fp2<C>);
impl_encoding!(impl [C: ark_ff::Fp3Config] for ark_ff::Fp3<C>);
impl_encoding!(impl [C: ark_ff::Fp4Config] for ark_ff::Fp4<C>);
impl_encoding!(impl [C: ark_ff::Fp6Config] for ark_ff::Fp6<C>);
impl_encoding!(impl [C: ark_ff::Fp12Config] for ark_ff::Fp12<C>);
impl_encoding!(impl [P: SmallFpConfig] for SmallFp<P>);
// Implement Decoding for prime-order fields and field extensions.
impl_decoding!(impl [C: FpConfig<N>, const N: usize] for Fp<C, N>);
impl_decoding!(impl [C: ark_ff::Fp2Config] for ark_ff::Fp2<C>);
impl_decoding!(impl [C: ark_ff::Fp3Config] for ark_ff::Fp3<C>);
impl_decoding!(impl [C: ark_ff::Fp4Config] for ark_ff::Fp4<C>);
impl_decoding!(impl [C: ark_ff::Fp6Config] for ark_ff::Fp6<C>);
impl_decoding!(impl [C: ark_ff::Fp12Config] for ark_ff::Fp12<C>);
impl_decoding!(impl [P: SmallFpConfig] for SmallFp<P>);

impl<F: Field> Default for DecodingFieldBuffer<F> {
    fn default() -> Self {
        let base_field_modulus_bytes = u64::from(F::BasePrimeField::MODULUS_BIT_SIZE.div_ceil(8));
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
