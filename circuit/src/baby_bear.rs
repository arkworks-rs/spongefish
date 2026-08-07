//! [`spongefish::Unit`] support for `p3_baby_bear::BabyBear`.
//!
//! A direct `impl Unit for BabyBear` would violate the orphan rule, so the
//! field is carried through the transparent [`BabyBearUnit`] wrapper.

use alloc::vec::Vec;

use p3_baby_bear::BabyBear;
use p3_field::{integers::QuotientMap, PrimeCharacteristicRing};
use spongefish::{Unit, UnitFromBytes};

/// Transparent [`Unit`] wrapper around [`BabyBear`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BabyBearUnit(pub BabyBear);

impl Unit for BabyBearUnit {
    const ZERO: Self = Self(BabyBear::ZERO);
}

impl From<BabyBear> for BabyBearUnit {
    fn from(value: BabyBear) -> Self {
        Self(value)
    }
}

impl From<BabyBearUnit> for BabyBear {
    fn from(value: BabyBearUnit) -> Self {
        value.0
    }
}

/// Reads a byte string as BabyBear units, one element per byte.
///
/// This is what lets a sponge over [`BabyBearUnit`] be seeded from a session
/// identifier: [`DuplexSponge`][spongefish::DuplexSponge] implements
/// [`DuplexSpongeInit`][spongefish::DuplexSpongeInit] over any alphabet that
/// byte strings embed into. With it,
/// [`ProverState::new`][spongefish::ProverState::new] and
/// [`from_tag_with`][spongefish::ProverState::from_tag_with] work over BabyBear
/// exactly as they do over bytes.
///
/// One element per byte rather than a denser packing: every element is then in
/// `[0, 256)`, so the map is injective by inspection and there is no remainder
/// case to get wrong. A 32-byte session identifier costs 32 units, absorbed
/// once per proof.
///
/// # Safety
///
/// Like the identity embedding on bytes, this map is injective but **not**
/// prefix-free across lengths: `b"ab"` maps to a prefix of `b"abc"`. It is
/// admissible where the byte length is fixed by the protocol — a session
/// identifier is always 32 bytes — and a variable-length byte string must be
/// length-prefixed by the caller.
impl UnitFromBytes for BabyBearUnit {
    fn encode_bytes(bytes: &[u8]) -> impl AsRef<[Self]> {
        bytes
            .iter()
            .map(|&byte| Self(BabyBear::from_int(byte)))
            .collect::<Vec<_>>()
    }
}

impl core::ops::Deref for BabyBearUnit {
    type Target = BabyBear;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
