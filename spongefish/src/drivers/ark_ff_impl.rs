//! Helpers for bridging `ark_ff` field types with `spongefish` codecs.
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use ark_ff::{BigInteger, Field, Fp, FpConfig, PrimeField, SmallFp, SmallFpConfig};

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

// Make SmallFp field elements a valid Unit type
impl<P: SmallFpConfig> crate::Unit for SmallFp<P> {
    const ZERO: Self = P::ZERO;
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
                    let elem = <<Self as Field>::BasePrimeField as PrimeField>::from_be_bytes_mod_order(chunk);
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
/// We work around that implementing [NargSerialize][`spongefish::NargSerialize`] for those types ourselves.
macro_rules! impl_encoding {
    (impl [$($generics:tt)*] for $type:ty) => {
        impl<$($generics)*> Encoding<[u8]> for $type {
            fn encode(&self) -> impl AsRef<[u8]> {
                let base_field_size = (<Self as Field>::BasePrimeField::MODULUS_BIT_SIZE
                    .div_ceil(8)) as usize;
                let mut buf = Vec::with_capacity(base_field_size * <Self as Field>::extension_degree() as usize);
                for base_element in self.to_base_prime_field_elements() {
                    let bytes = base_element.into_bigint().to_bytes_be();
                    // Handle BigInt wider than the field (SmallFp: BigInt<2> for 8-byte field).
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
            type Repr = DecodingFieldBuffer<$type>;

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
// SmallFp NargDeserialize: read exactly ⌈MODULUS_BIT_SIZE / 8⌉ BE bytes and
// reconstruct via the field's canonical PrimeField::BigInt type. We can't use the
// macro because `from_be_bytes_mod_order` reduces non-canonical encodings instead
// of rejecting them.
impl<P: SmallFpConfig> NargDeserialize for SmallFp<P> {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        let base_field_size = (Self::MODULUS_BIT_SIZE.div_ceil(8)) as usize;
        if buf.len() < base_field_size {
            return Err(VerificationError);
        }
        let (head, tail) = buf.split_at(base_field_size);
        *buf = tail;
        let bits = head
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1 == 1))
            .collect::<Vec<_>>();
        let bigint = <Self as PrimeField>::BigInt::from_bits_be(&bits);
        Self::from_bigint(bigint).ok_or(VerificationError)
    }
}
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

// SmallFp Encoding: serialize exactly ⌈MODULUS_BIT_SIZE / 8⌉ bytes per element,
// computed from the modulus rather than the BigInt backing width.
impl<P: SmallFpConfig> Encoding<[u8]> for SmallFp<P> {
    fn encode(&self) -> impl AsRef<[u8]> {
        let base_field_size = (Self::MODULUS_BIT_SIZE.div_ceil(8)) as usize;
        let mut bytes = self.into_bigint().to_bytes_be();
        // BigInt<2> produces 16 BE bytes; drop the leading zeros to keep
        // only the ⌈MODULUS_BIT_SIZE / 8⌉ significant bytes.
        bytes.drain(..bytes.len() - base_field_size);
        bytes
    }
}

// SmallFp Decoding: uniform random sampling from squeezed bytes.
impl<P: SmallFpConfig> Decoding<[u8]> for SmallFp<P> {
    type Repr = DecodingFieldBuffer<SmallFp<P>>;

    fn decode(repr: Self::Repr) -> Self {
        debug_assert_eq!(repr.buf.len(), decoding_field_buffer_size::<Self>());
        Self::from_le_bytes_mod_order(&repr.buf)
    }
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

#[cfg(test)]
mod test_ark_ff {
    use ark_ff::BigInteger;

    use crate::{codecs::Encoding, io::NargSerialize};

    // ----- SmallFp test fields -----

    // Goldilocks field: p = 2^64 - 2^32 + 1
    ark_ff::define_field!(
        modulus = "18446744069414584321",
        generator = "7",
        name = Goldilocks,
    );

    // Mersenne31 field: p = 2^31 - 1
    ark_ff::define_field!(modulus = "2147483647", generator = "7", name = M31,);

    // BabyBear field: p = 15 * 2^27 + 1
    ark_ff::define_field!(modulus = "2013265921", generator = "31", name = BabyBear,);

    // KoalaBear field: p = 2^31 - 2^24 + 1
    ark_ff::define_field!(modulus = "2130706433", generator = "3", name = KoalaBear,);

    // A 16-bit test field: p = 65521 (largest 16-bit prime)
    ark_ff::define_field!(modulus = "65521", generator = "17", name = F16,);

    // ----- Encoding / serialization round-trip tests -----

    /// Encode → serialize → deserialize round-trip, testing zero, one, p-1,
    /// and a handful of interior values.
    fn roundtrip_testsuite<F>()
    where
        F: ark_ff::PrimeField
            + Encoding<[u8]>
            + crate::io::NargSerialize
            + crate::io::NargDeserialize,
    {
        for v in [0u64, 1, 42, 12345] {
            let original = F::from(v);
            let serialized = encode_to_vec(&original);
            let mut slice: &[u8] = &serialized;
            let deserialized = F::deserialize_from_narg(&mut slice)
                .unwrap_or_else(|_| panic!("failed to deserialize value {v}"));
            assert!(
                slice.is_empty(),
                "deserialize did not consume all bytes for value {v}"
            );
            assert_eq!(original, deserialized, "roundtrip mismatch for {v}");
        }

        // p - 1 (the largest valid element)
        let p_minus_1 = -F::ONE;
        let ser = encode_to_vec(&p_minus_1);
        let mut sl: &[u8] = &ser;
        let de = F::deserialize_from_narg(&mut sl).expect("p-1 should deserialize");
        assert!(sl.is_empty());
        assert_eq!(de, p_minus_1);
    }

    fn encode_to_vec<F: Encoding<[u8]>>(x: &F) -> alloc::vec::Vec<u8> {
        let mut dst = alloc::vec::Vec::new();
        x.serialize_into_narg(&mut dst);
        dst
    }

    /// Encoding the same value twice must produce identical bytes.
    fn deterministic_encoding_testsuite<F: ark_ff::Field + Encoding<[u8]>>() {
        for v in [0u64, 1, 42, 12345] {
            let elem = F::from(v);
            let a = encode_to_vec(&elem);
            let b = encode_to_vec(&elem);
            assert_eq!(a, b, "encoding not deterministic for {v}");
        }
    }

    /// Distinct values must encode differently.
    fn distinct_values_encode_differently<F: ark_ff::PrimeField + Encoding<[u8]>>() {
        let zero = encode_to_vec(&F::ZERO);
        let one = encode_to_vec(&F::ONE);
        let p_minus_1 = encode_to_vec(&(-F::ONE));

        assert_ne!(zero, one);
        assert_ne!(one, p_minus_1);
        assert_ne!(zero, p_minus_1);
    }

    /// Deserializing p (the modulus itself) must fail — the encoding
    /// is not canonical because p ≡ 0 and 0 already has its own encoding.
    fn reject_modulus<F: ark_ff::PrimeField + core::fmt::Debug + crate::io::NargDeserialize>() {
        let modulus_bytes = F::MODULUS.to_bytes_be();
        // Keep only the trailing ⌈MODULUS_BIT_SIZE/8⌉ bytes (SmallFp BigInt<2>
        // produces 16 BE bytes but the serialisation is shorter).
        let field_size = F::MODULUS_BIT_SIZE.div_ceil(8) as usize;
        let start = modulus_bytes.len().saturating_sub(field_size);
        let trimmed = &modulus_bytes[start..];
        let mut sl: &[u8] = trimmed;
        assert!(
            F::deserialize_from_narg(&mut sl).is_err(),
            "deserializing p should fail (modulus_bits={}, field_size={field_size}, trimmed={trimmed:?})",
            F::MODULUS_BIT_SIZE,
        );
    }

    /// A single bit-flip must either change the decoded value or cause rejection.
    fn bitflip_testsuite<F>()
    where
        F: ark_ff::PrimeField + Encoding<[u8]> + crate::io::NargDeserialize,
    {
        let original = F::from(42u64);
        let encoded = encode_to_vec(&original);

        for byte_idx in 0..encoded.len() {
            for bit in 0..8u8 {
                let mut flipped = encoded.clone();
                flipped[byte_idx] ^= 1 << bit;
                let mut sl: &[u8] = &flipped;
                match F::deserialize_from_narg(&mut sl) {
                    Ok(v) => assert_ne!(
                        v, original,
                        "bit-flip at byte {byte_idx} bit {bit} decoded to same value"
                    ),
                    Err(_) => {} // rejection is fine
                }
            }
        }
    }

    /// Truncated buffer must be rejected.
    fn wrong_length_testsuite<F>()
    where
        F: ark_ff::PrimeField + Encoding<[u8]> + crate::io::NargDeserialize,
    {
        let encoded = encode_to_vec(&F::from(1u64));

        // Truncated: one byte short
        if !encoded.is_empty() {
            let short = &encoded[..encoded.len() - 1];
            let mut sl: &[u8] = short;
            assert!(
                F::deserialize_from_narg(&mut sl).is_err(),
                "truncated buffer should fail"
            );
        }
    }

    #[test]
    fn test_smallfp_roundtrip() {
        roundtrip_testsuite::<Goldilocks>();
        roundtrip_testsuite::<M31>();
        roundtrip_testsuite::<BabyBear>();
        roundtrip_testsuite::<KoalaBear>();
        roundtrip_testsuite::<F16>();
    }

    #[test]
    fn test_smallfp_deterministic_encoding() {
        deterministic_encoding_testsuite::<Goldilocks>();
        deterministic_encoding_testsuite::<M31>();
        deterministic_encoding_testsuite::<BabyBear>();
        deterministic_encoding_testsuite::<KoalaBear>();
        deterministic_encoding_testsuite::<F16>();
    }

    #[test]
    fn test_smallfp_distinct_values_encode_differently() {
        distinct_values_encode_differently::<Goldilocks>();
        distinct_values_encode_differently::<M31>();
        distinct_values_encode_differently::<BabyBear>();
        distinct_values_encode_differently::<KoalaBear>();
        distinct_values_encode_differently::<F16>();
    }

    #[test]
    fn test_smallfp_reject_modulus() {
        reject_modulus::<Goldilocks>();
        reject_modulus::<M31>();
        reject_modulus::<BabyBear>();
        reject_modulus::<KoalaBear>();
        // F16 modulus is 65521, which fits in 2 bytes. Encoding is 2 BE bytes.
        reject_modulus::<F16>();
    }

    #[test]
    fn test_smallfp_bitflip() {
        bitflip_testsuite::<Goldilocks>();
        bitflip_testsuite::<M31>();
        bitflip_testsuite::<BabyBear>();
        bitflip_testsuite::<KoalaBear>();
        bitflip_testsuite::<F16>();
    }

    #[test]
    fn test_smallfp_wrong_length() {
        wrong_length_testsuite::<Goldilocks>();
        wrong_length_testsuite::<M31>();
        wrong_length_testsuite::<BabyBear>();
        wrong_length_testsuite::<KoalaBear>();
        wrong_length_testsuite::<F16>();
    }

    // ----- MontFp (large field) tests -----

    #[test]
    fn test_montfp_roundtrip() {
        roundtrip_testsuite::<ark_bls12_381::Fr>();
        roundtrip_testsuite::<ark_bls12_381::Fq>();
    }

    #[test]
    fn test_montfp_reject_modulus() {
        reject_modulus::<ark_bls12_381::Fr>();
        reject_modulus::<ark_bls12_381::Fq>();
    }

    #[test]
    fn test_montfp_bitflip() {
        bitflip_testsuite::<ark_bls12_381::Fr>();
    }

    // ----- SmallFp extension field (Fp2) -----

    pub struct GoldilocksFp2Config;
    impl ark_ff::Fp2Config for GoldilocksFp2Config {
        type Fp = Goldilocks;

        // 7 is a quadratic non-residue mod Goldilocks
        const NONRESIDUE: Self::Fp = ark_ff::SmallFp::from_raw(7);

        const FROBENIUS_COEFF_FP2_C1: &'static [Self::Fp] = &[
            // 7^(((q^0) - 1) / 2) = 1
            ark_ff::SmallFp::from_raw(1),
            // 7^(((q^1) - 1) / 2) = p - 1
            ark_ff::SmallFp::from_raw(18446744069414584320),
        ];
    }
    pub type GoldilocksFp2 = ark_ff::Fp2<GoldilocksFp2Config>;

    #[test]
    fn test_encoding_small_fp_goldilocks_fp2() {
        deterministic_encoding_testsuite::<GoldilocksFp2>();
    }

    #[test]
    fn test_prime_field_encoding_is_left_padded_big_endian() {
        let value = ark_secp256k1::Fr::from(1u64);
        let encoded = Encoding::<[u8]>::encode(&value);
        let bytes = encoded.as_ref();

        assert_eq!(bytes.len(), 32);
        assert!(bytes[..31].iter().all(|&byte| byte == 0));
        assert_eq!(bytes[31], 1);
    }
}
