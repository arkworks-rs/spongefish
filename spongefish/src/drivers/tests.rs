use alloc::vec::Vec;

use crate::{
    codecs::{Decoding, Encoding},
    io::{NargDeserialize, NargSerialize},
};

fn encoded_bytes<T: Encoding<[u8]>>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn assert_roundtrip<T>(value: &T)
where
    T: Encoding<[u8]> + NargSerialize + NargDeserialize,
{
    let serialized = value.serialize_into_new_narg();
    let mut slice: &[u8] = serialized.as_ref();
    let decoded = T::deserialize_from_narg(&mut slice).expect("failed to deserialize");
    assert!(slice.is_empty(), "deserialize did not consume all bytes");
    assert_eq!(encoded_bytes(value), encoded_bytes(&decoded));
}

fn assert_narg_advances_buffer<T>(value: &T)
where
    T: NargSerialize + NargDeserialize,
{
    const TRAILING: u8 = 0x42;
    let mut buf = Vec::new();
    value.serialize_into_narg(&mut buf);
    buf.push(TRAILING);

    let mut slice: &[u8] = &buf;
    T::deserialize_from_narg(&mut slice).expect("failed to deserialize");
    assert_eq!(
        slice,
        &[TRAILING],
        "buffer not advanced correctly: expected 1 trailing byte, got {}",
        slice.len()
    );
}

#[allow(unused)]
fn assert_codec_compatibility<A, B>(value_a: &A, value_b: &B)
where
    A: Encoding<[u8]> + NargSerialize + NargDeserialize,
    B: Encoding<[u8]> + NargSerialize + NargDeserialize,
{
    assert_eq!(encoded_bytes(value_a), encoded_bytes(value_b));

    assert_roundtrip(value_a);
    assert_roundtrip(value_b);

    let serialized_a = value_a.serialize_into_new_narg();
    let mut slice_a: &[u8] = serialized_a.as_ref();
    let decoded_b =
        B::deserialize_from_narg(&mut slice_a).expect("failed to deserialize bytes from A");
    assert!(slice_a.is_empty(), "deserialize did not consume all bytes");
    assert_eq!(encoded_bytes(&decoded_b), encoded_bytes(value_b));

    let serialized_b = value_b.serialize_into_new_narg();
    let mut slice_b: &[u8] = serialized_b.as_ref();
    let decoded_a =
        A::deserialize_from_narg(&mut slice_b).expect("failed to deserialize bytes from B");
    assert!(slice_b.is_empty(), "deserialize did not consume all bytes");
    assert_eq!(encoded_bytes(&decoded_a), encoded_bytes(value_a));
}

#[allow(unused)]
fn assert_decoding_compatibility<A, B>()
where
    A: Encoding<[u8]> + Decoding<[u8]>,
    B: Encoding<[u8]> + Decoding<[u8]>,
{
    let mut repr_a = A::Repr::default();
    let len_a = {
        let slice = repr_a.as_mut();
        slice.len()
    };

    let mut repr_b = B::Repr::default();
    let len_b = {
        let slice = repr_b.as_mut();
        slice.len()
    };

    assert_eq!(len_a, len_b, "decoding buffer size mismatch");

    let pattern: Vec<u8> = (0..len_a)
        .map(|i| (i.wrapping_mul(17).wrapping_add(3)) as u8)
        .collect();

    repr_a.as_mut().copy_from_slice(&pattern);
    repr_b.as_mut().copy_from_slice(&pattern);

    let decoded_a = A::decode(repr_a);
    let decoded_b = B::decode(repr_b);

    assert_eq!(encoded_bytes(&decoded_a), encoded_bytes(&decoded_b));
}

#[cfg(all(
    feature = "p3-baby-bear",
    feature = "p3-koala-bear",
    feature = "p3-mersenne-31"
))]
#[test]
fn p3_field_deserialize_advances_cursor() {
    use p3_baby_bear::BabyBear;
    use p3_koala_bear::KoalaBear;
    use p3_mersenne_31::Mersenne31;

    let mut baby = &[0, 0, 0, 1, 9][..];
    assert!(BabyBear::deserialize_from_narg(&mut baby).is_ok());
    assert_eq!(baby, &[9]);
    let mut koala = &[0, 0, 0, 1, 9][..];
    assert!(KoalaBear::deserialize_from_narg(&mut koala).is_ok());
    assert_eq!(koala, &[9]);
    let mut mersenne = &[0, 0, 0, 1, 9][..];
    assert!(Mersenne31::deserialize_from_narg(&mut mersenne).is_ok());
    assert_eq!(mersenne, &[9]);
}

#[cfg(all(
    feature = "p3-baby-bear",
    feature = "p3-koala-bear",
    feature = "p3-mersenne-31"
))]
#[test]
fn p3_field_deserialize_rejects_without_advancing_cursor() {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;
    use p3_koala_bear::KoalaBear;
    use p3_mersenne_31::Mersenne31;

    let baby_buf = [BabyBear::ORDER_U32.to_be_bytes().as_slice(), &[9]].concat();
    let mut baby = baby_buf.as_slice();
    assert!(BabyBear::deserialize_from_narg(&mut baby).is_err());
    assert_eq!(baby, baby_buf.as_slice());

    let koala_buf = [KoalaBear::ORDER_U32.to_be_bytes().as_slice(), &[9]].concat();
    let mut koala = koala_buf.as_slice();
    assert!(KoalaBear::deserialize_from_narg(&mut koala).is_err());
    assert_eq!(koala, koala_buf.as_slice());

    let mersenne_buf = [Mersenne31::ORDER_U32.to_be_bytes().as_slice(), &[9]].concat();
    let mut mersenne = mersenne_buf.as_slice();
    assert!(Mersenne31::deserialize_from_narg(&mut mersenne).is_err());
    assert_eq!(mersenne, mersenne_buf.as_slice());
}

#[cfg(feature = "p3-baby-bear")]
#[test]
fn array_deserialize_rejects_without_advancing_cursor() {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    let input = [
        1u32.to_be_bytes().as_slice(),
        BabyBear::ORDER_U32.to_be_bytes().as_slice(),
        &[9],
    ]
    .concat();
    let mut slice = input.as_slice();

    assert!(<[BabyBear; 2]>::deserialize_from_narg(&mut slice).is_err());
    assert_eq!(slice, input.as_slice());
}

#[cfg(all(feature = "ark-ec", feature = "curve25519-dalek"))]
#[test]
fn curve25519_scalars_arkworks_and_dalek() {
    use ark_curve25519::Fr as ArkScalar;
    use curve25519_dalek::scalar::Scalar as DalekScalar;

    for value in [0u64, 1, 42, 123_456_789] {
        let ark_scalar = ArkScalar::from(value);
        let dalek_scalar = DalekScalar::from(value);
        assert_codec_compatibility(&ark_scalar, &dalek_scalar);
    }

    assert_decoding_compatibility::<ArkScalar, DalekScalar>();
}

#[cfg(all(feature = "ark-ec", feature = "k256"))]
#[test]
fn secp256k1_scalars_arkworks_and_k256() {
    use ark_secp256k1::Fr as ArkScalar;
    use k256::Scalar as K256Scalar;

    for value in [0u64, 1, 42, 123_456_789] {
        let ark_scalar = ArkScalar::from(value);
        let k256_scalar = K256Scalar::from(value);
        assert_codec_compatibility(&ark_scalar, &k256_scalar);
    }

    assert_decoding_compatibility::<ArkScalar, K256Scalar>();
}

#[cfg(all(feature = "ark-ec", feature = "p256"))]
#[test]
fn secp256r1_scalars_arkworks_and_p256() {
    use ::p256::Scalar as P256Scalar;
    type ArkP256Scalar = <ark_secp256r1::Projective as ark_ec::PrimeGroup>::ScalarField;

    for value in [0u64, 1, 42, 123_456_789] {
        let ark_scalar = ArkP256Scalar::from(value);
        let p256_scalar = P256Scalar::from(value);
        assert_codec_compatibility(&ark_scalar, &p256_scalar);
    }

    assert_decoding_compatibility::<ArkP256Scalar, P256Scalar>();
}

#[cfg(all(feature = "ark-ff", feature = "p3-baby-bear"))]
#[test]
fn babybear_scalars_arkworks_and_p3() {
    ark_ff::define_field!(
        modulus = "2013265921",
        generator = "31",
        name = ArkBabyBear,
    );

    for value in [0u64, 1, 42, 123_456_789] {
        let ark_scalar = ArkBabyBear::from(value);
        let p3_scalar = p3_baby_bear::BabyBear::new(value as u32);
        assert_codec_compatibility(&ark_scalar, &p3_scalar);
    }
}

#[cfg(all(feature = "ark-ff", feature = "p3-koala-bear"))]
#[test]
fn koalabear_scalars_arkworks_and_p3() {
    ark_ff::define_field!(
        modulus = "2130706433",
        generator = "3",
        name = ArkKoalaBear,
    );

    for value in [0u64, 1, 42, 123_456_789] {
        let ark_scalar = ArkKoalaBear::from(value);
        let p3_scalar = p3_koala_bear::KoalaBear::new(value as u32);
        assert_codec_compatibility(&ark_scalar, &p3_scalar);
    }
}

#[cfg(feature = "ark-ff")]
#[test]
fn narg_ark_ff_advances_buffer() {
    use ark_ff::Field;

    for v in [0u64, 1, 42] {
        assert_narg_advances_buffer(&ark_bls12_381::Fr::from(v));
        assert_narg_advances_buffer(&ark_bls12_381::Fq::from(v));
        assert_narg_advances_buffer(&ark_secp256k1::Fr::from(v));
    }

    let fq2 = ark_bls12_381::Fq2::from_base_prime_field_elems([
        ark_bls12_381::Fq::from(0u64),
        ark_bls12_381::Fq::from(42u64),
    ])
    .unwrap();
    assert_narg_advances_buffer(&fq2);
}

#[cfg(feature = "ark-ec")]
#[test]
fn narg_ark_ec_advances_buffer() {
    use ark_ec::PrimeGroup;
    assert_narg_advances_buffer(&ark_pallas::Projective::generator());
    assert_narg_advances_buffer(&ark_vesta::Projective::generator());
}

#[cfg(feature = "curve25519-dalek")]
#[test]
fn narg_curve25519_dalek_advances_buffer() {
    use curve25519_dalek::{constants, scalar::Scalar};

    for v in [0u64, 1, 42] {
        assert_narg_advances_buffer(&Scalar::from(v));
    }
    assert_narg_advances_buffer(&constants::ED25519_BASEPOINT_POINT);
    assert_narg_advances_buffer(&constants::RISTRETTO_BASEPOINT_POINT);
}

#[cfg(feature = "bls12_381")]
#[test]
fn narg_bls12_381_advances_buffer() {
    use bls12_381::{G1Projective, G2Projective, Scalar};

    for v in [0u64, 1, 42] {
        assert_narg_advances_buffer(&Scalar::from(v));
    }
    assert_narg_advances_buffer(&G1Projective::generator());
    assert_narg_advances_buffer(&G2Projective::generator());
}

#[cfg(feature = "k256")]
#[test]
fn narg_k256_advances_buffer() {
    use k256::{ProjectivePoint, Scalar};

    for v in [0u64, 1, 42] {
        assert_narg_advances_buffer(&Scalar::from(v));
    }
    assert_narg_advances_buffer(&ProjectivePoint::GENERATOR);
}

#[cfg(feature = "p256")]
#[test]
fn narg_p256_advances_buffer() {
    use p256::{ProjectivePoint, Scalar};

    for v in [0u64, 1, 42] {
        assert_narg_advances_buffer(&Scalar::from(v));
    }
    assert_narg_advances_buffer(&ProjectivePoint::GENERATOR);
}

#[cfg(feature = "p3-baby-bear")]
#[test]
fn narg_p3_baby_bear_advances_buffer() {
    use p3_baby_bear::BabyBear;

    for v in [0u32, 1, 42] {
        assert_narg_advances_buffer(&BabyBear::new(v));
    }
}

#[cfg(feature = "p3-koala-bear")]
#[test]
fn narg_p3_koala_bear_advances_buffer() {
    use p3_koala_bear::KoalaBear;

    for v in [0u32, 1, 42] {
        assert_narg_advances_buffer(&KoalaBear::new(v));
    }
}

#[cfg(feature = "p3-mersenne-31")]
#[test]
fn narg_p3_mersenne31_advances_buffer() {
    use p3_mersenne_31::Mersenne31;

    for v in [0u32, 1, 42] {
        assert_narg_advances_buffer(&Mersenne31::new(v));
    }
}
