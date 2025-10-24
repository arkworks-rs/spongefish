use alloc::vec::Vec;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{codecs::Encoding, error::VerificationError, io::Deserialize, VerificationResult};

// Use the macro to implement Deserialize for various arkworks elliptic curves
macro_rules! impl_deserialize {
    (impl [$($generics:tt)*] for $type:ty) => {
        impl<$($generics)*> Deserialize for $type {
            fn deserialize_from(buf: &mut &[u8]) -> VerificationResult<Self> {
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

impl_deserialize!(impl [P: ark_ec::short_weierstrass::SWCurveConfig] for ark_ec::short_weierstrass::Projective<P>);
impl_deserialize!(impl [P: ark_ec::short_weierstrass::SWCurveConfig] for ark_ec::short_weierstrass::Affine<P>);
impl_deserialize!(impl [P: ark_ec::twisted_edwards::TECurveConfig] for ark_ec::twisted_edwards::Projective<P>);
impl_deserialize!(impl [P: ark_ec::twisted_edwards::TECurveConfig] for ark_ec::twisted_edwards::Affine<P>);
impl_deserialize!(impl [P: ark_ec::pairing::Pairing] for ark_ec::pairing::PairingOutput<P>);

// Implement Encoding for specific arkworks curve group elements

// implement Encoding for various arkworks field types
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

impl_encoding!(impl [P: ark_ec::short_weierstrass::SWCurveConfig] for ark_ec::short_weierstrass::Projective<P>);
impl_encoding!(impl [P: ark_ec::short_weierstrass::SWCurveConfig] for ark_ec::short_weierstrass::Affine<P>);
impl_encoding!(impl [P: ark_ec::twisted_edwards::TECurveConfig] for ark_ec::twisted_edwards::Projective<P>);
impl_encoding!(impl [P: ark_ec::twisted_edwards::TECurveConfig] for ark_ec::twisted_edwards::Affine<P>);
impl_encoding!(impl [P: ark_ec::pairing::Pairing] for ark_ec::pairing::PairingOutput<P>);
