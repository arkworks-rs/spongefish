#![cfg(feature = "derive")]

use core::marker::PhantomData;

#[cfg(feature = "p3-baby-bear")]
use p3_baby_bear::BabyBear;
#[cfg(feature = "p3-baby-bear")]
use p3_field::PrimeField32;
use spongefish::{Codec, Encoding, NargDeserialize, NargSerialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Codec)]
struct TaggedValue<T, const N: usize> {
    value: u32,
    #[spongefish(skip)]
    _marker: PhantomData<(T, [(); N])>,
}

#[cfg(feature = "p3-baby-bear")]
#[allow(dead_code)]
#[derive(Debug, spongefish::NargDeserialize)]
struct TwoBabyBears {
    first: BabyBear,
    second: BabyBear,
}

#[test]
fn codec_derive_handles_generic_types() {
    let tagged = TaggedValue::<u8, 4> {
        value: 7,
        _marker: PhantomData,
    };

    let encoded = tagged.encode();
    assert_eq!(encoded.as_ref(), 7u32.to_le_bytes());

    let serialized = tagged.serialize_into_new_narg();
    let mut buf: &[u8] = serialized.as_ref();
    let roundtrip = TaggedValue::<u8, 4>::deserialize_from_narg(&mut buf).expect("roundtrip");
    assert_eq!(roundtrip.value, tagged.value);
    assert!(buf.is_empty());

    #[allow(clippy::items_after_statements)]
    fn assert_codec<T: Codec>(_: &T) {}
    assert_codec(&tagged);
}

#[test]
#[cfg(feature = "p3-baby-bear")]
fn derive_deserialize_rejects_without_advancing_cursor() {
    let input = [
        1u32.to_le_bytes().as_slice(),
        BabyBear::ORDER_U32.to_le_bytes().as_slice(),
        &[9],
    ]
    .concat();
    let mut slice = input.as_slice();

    assert!(TwoBabyBears::deserialize_from_narg(&mut slice).is_err());
    assert_eq!(slice, input.as_slice());
}
