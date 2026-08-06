#![cfg(feature = "derive")]

use core::marker::PhantomData;

use spongefish::{Codec, Encoding, NargDeserialize, NargSerialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Codec)]
struct TaggedValue<T, const N: usize> {
    value: u32,
    #[spongefish(skip)]
    _marker: PhantomData<(T, [(); N])>,
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
