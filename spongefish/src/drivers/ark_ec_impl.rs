//! Helpers for bridging `ark_ec` curve types with `spongefish` codecs.

use alloc::vec::Vec;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{codecs::Encoding, error::VerificationError, io::NargDeserialize, VerificationResult};

macro_rules! impl_deserialize {
    (impl [$($generics:tt)*] for $type:ty) => {
        impl<$($generics)*> NargDeserialize for $type {
            fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
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

// Implement Deserialize for elliptic curve structs
impl_deserialize!(impl [P: ark_ec::short_weierstrass::SWCurveConfig] for ark_ec::short_weierstrass::Projective<P>);
impl_deserialize!(impl [P: ark_ec::short_weierstrass::SWCurveConfig] for ark_ec::short_weierstrass::Affine<P>);
impl_deserialize!(impl [P: ark_ec::twisted_edwards::TECurveConfig] for ark_ec::twisted_edwards::Projective<P>);
impl_deserialize!(impl [P: ark_ec::twisted_edwards::TECurveConfig] for ark_ec::twisted_edwards::Affine<P>);
impl_deserialize!(impl [P: ark_ec::pairing::Pairing] for ark_ec::pairing::PairingOutput<P>);

// Implement Encoding for elliptic curve structs.
// Note: NargSerialize will also be defined via the blanket implementation.
impl_encoding!(impl [P: ark_ec::short_weierstrass::SWCurveConfig] for ark_ec::short_weierstrass::Projective<P>);
impl_encoding!(impl [P: ark_ec::short_weierstrass::SWCurveConfig] for ark_ec::short_weierstrass::Affine<P>);
impl_encoding!(impl [P: ark_ec::twisted_edwards::TECurveConfig] for ark_ec::twisted_edwards::Projective<P>);
impl_encoding!(impl [P: ark_ec::twisted_edwards::TECurveConfig] for ark_ec::twisted_edwards::Affine<P>);
impl_encoding!(impl [P: ark_ec::pairing::Pairing] for ark_ec::pairing::PairingOutput<P>);
