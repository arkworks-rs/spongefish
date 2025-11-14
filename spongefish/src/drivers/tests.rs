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

// #[cfg(all(feature = "ark-ec", feature = "p256"))]
// mod p256 {
//     use super::*;
//     use ark_ec::PrimeGroup;
//     use ark_pallas::Projective as ArkProjective;
//     use p256::{ProjectivePoint, Scalar as P256Scalar};

//     type ArkScalar = <ArkProjective as PrimeGroup>::ScalarField;

//     #[test]
//     fn scalars_are_codec_compatible() {
//         for value in [0u64, 1, 42, 123_456_789] {
//             let ark_scalar = ArkScalar::from(value);
//             let p256_scalar = P256Scalar::from(value);
//             assert_codec_compatibility(&ark_scalar, &p256_scalar);
//         }

//         assert_decoding_compatibility::<ArkScalar, P256Scalar>();
//     }
// }
