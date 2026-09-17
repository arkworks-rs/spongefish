#![cfg(feature = "derive")]

use core::marker::PhantomData;

use spongefish::{hybrid_array::AsArrayMut, Codec, Decoding, Encoding, NargReader};

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

    let serialized = tagged.encode();
    let mut reader = NargReader::new(serialized.as_ref());
    let roundtrip = reader.read::<TaggedValue<u8, 4>>().expect("roundtrip");
    assert_eq!(roundtrip.value, tagged.value);
    assert!(reader.is_empty());

    #[allow(clippy::items_after_statements)]
    fn assert_codec<T: Codec>(_: &T) {}
    assert_codec(&tagged);
}

/// Mixed field widths, so an off-by-one in the derived offsets shows up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Codec)]
struct Header {
    tag: u8,
    id: u32,
    #[spongefish(skip)]
    cached: u32,
    nonce: u64,
}

/// The tuple-struct branch of the derive, with a skipped trailing field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Codec)]
struct Pair(u16, u8, #[spongefish(skip)] u32);

/// Builds a `Decoding::Repr` out of raw bytes, the way the sponge fills it.
fn repr<T: Decoding>(bytes: &[u8]) -> T::Repr {
    let mut buffer = T::Repr::default();
    buffer.as_array_mut().copy_from_slice(bytes);
    buffer
}

/// Pins the byte layout of the derived codecs: fields are laid out in
/// declaration order, each at its own width, and skipped fields occupy no
/// bytes on the wire nor in the squeezed representation.
#[test]
fn codec_derive_pins_multi_field_byte_layout() {
    let header = Header {
        tag: 0xAA,
        id: 0x0102_0304,
        cached: 0xDEAD_BEEF,
        nonce: 0x0A0B_0C0D_0E0F_1011,
    };

    // Encoding: 1 + 4 + 8 bytes, little-endian, `cached` omitted.
    let expected = [
        0xAA, // tag
        0x04, 0x03, 0x02, 0x01, // id
        0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, // nonce
    ];
    assert_eq!(header.encode().as_ref(), &expected);

    // Decoding: the representation is exactly as wide as the encoding, and
    // consuming those same bytes reconstructs the non-skipped fields.
    assert_eq!(
        core::mem::size_of::<<Header as Decoding>::Repr>(),
        expected.len()
    );
    let decoded = Header::decode(repr::<Header>(&expected));
    assert_eq!(decoded.tag, header.tag);
    assert_eq!(decoded.id, header.id);
    assert_eq!(decoded.nonce, header.nonce);
    assert_eq!(decoded.cached, 0, "skipped fields decode to `Default`");

    // A distinct byte pattern, to catch offsets that happen to coincide.
    let shifted = [
        0x01, // tag
        0x02, 0x00, 0x00, 0x00, // id
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // nonce
    ];
    let decoded = Header::decode(repr::<Header>(&shifted));
    assert_eq!((decoded.tag, decoded.id, decoded.nonce), (1, 2, 3));

    // NARG round-trip keeps the same layout.
    let serialized = header.encode();
    assert_eq!(serialized.as_ref(), &expected);
    let mut reader = NargReader::new(serialized.as_ref());
    let roundtrip = reader.read::<Header>().expect("roundtrip");
    assert_eq!(roundtrip.id, header.id);
    assert!(reader.is_empty());

    // Tuple structs follow the same rules.
    let pair = Pair(0x0102, 0x03, 0xFFFF_FFFF);
    assert_eq!(pair.encode().as_ref(), &[0x02, 0x01, 0x03]);
    assert_eq!(core::mem::size_of::<<Pair as Decoding>::Repr>(), 3);
    let decoded = Pair::decode(repr::<Pair>(&[0x02, 0x01, 0x03]));
    assert_eq!(decoded, Pair(0x0102, 0x03, 0));
}
