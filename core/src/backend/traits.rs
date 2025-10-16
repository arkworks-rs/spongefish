use ark_ff::FpConfig;
use ark_serialize::CanonicalSerialize;

use crate::codecs::{Decodable, Encodable};

impl<C: FpConfig<N>, const N: usize> Encodable<[u8]> for ark_ff::Fp<C, N> {
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut w = alloc::vec::Vec::new();
        self.serialize_compressed(&mut w).expect("Unable to serialize element");
        w
    }
}


pub struct ScalarBuffer<const N: usize>(alloc::vec::Vec<u8>);

impl<const N: usize> Default for ScalarBuffer<N> {
    fn default() -> Self {
        let len = size_of::<u64>() * N + 32;
        ScalarBuffer(alloc::vec![0u8; len])
    }
}

impl<const N: usize> AsMut<[u8]> for ScalarBuffer<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

use ark_ff::PrimeField;

impl<const N: usize, C: FpConfig<N>> Decodable<[u8]> for ark_ff::Fp<C, N>
{
    type Repr = ScalarBuffer<N>;

    fn decode(buf: <Self as Decodable<[u8]>>::Repr) -> Self {
        Self::from_be_bytes_mod_order(&buf.0)
    }
}


macro_rules! field_traits {
    ($Field:path) => {
        /// Absorb and squeeze field elements to the domain separator.
        pub trait FieldDomainSeparator<F: $Field> {
            #[must_use]
            fn add_scalars(self, count: usize, label: &str) -> Self;
            #[must_use]
            fn challenge_scalars(self, count: usize, label: &str) -> Self;
        }

        /// Interpret verifier messages as uniformly distributed field elements.
        ///
        /// The implementation of this trait **MUST** ensure that the field elementsxx
        pub trait UnitToField<F: $Field> {
            fn fill_challenge_scalars(&mut self, output: &mut [F]) -> $crate::ProofResult<()>;

            fn challenge_scalars<const N: usize>(&mut self) -> crate::ProofResult<[F; N]> {
                let mut output = [F::default(); N];
                self.fill_challenge_scalars(&mut output)?;
                Ok(output)
            }
        }

        /// Add field elements as shared public information.
        pub trait CommonFieldToUnit<F: $Field> {
            type Repr;
            fn public_scalars(&mut self, input: &[F]) -> crate::ProofResult<Self::Repr>;
        }

        /// Add field elements to the protocol transcript.
        pub trait FieldToUnitSerialize<F: $Field>: CommonFieldToUnit<F> {
            fn add_scalars(&mut self, input: &[F]) -> crate::ProofResult<()>;
        }

        /// Deserialize field elements from the protocol transcript.
        ///
        /// The implementation of this trait **MUST** ensure that the field elements
        /// are correct encodings.
        pub trait FieldToUnitDeserialize<F: $Field>: CommonFieldToUnit<F> {
            fn fill_next_scalars(&mut self, output: &mut [F]) -> crate::ProofResult<()>;

            fn next_scalars<const N: usize>(&mut self) -> crate::ProofResult<[F; N]> {
                let mut output = [F::default(); N];
                self.fill_next_scalars(&mut output)?;
                Ok(output)
            }
        }
    };
}

#[macro_export]
macro_rules! group_traits {
    ($Group:path, Scalar: $Field:path) => {
        /// Send group elements in the domain separator.
        pub trait GroupDomainSeparator<G: $Group> {
            #[must_use]
            fn add_points(self, count: usize, label: &str) -> Self;
        }

        /// Adds a new prover message consisting of an EC element.
        pub trait GroupToUnitSerialize<G: $Group>: CommonGroupToUnit<G> {
            fn add_points(&mut self, input: &[G]) -> $crate::ProofResult<()>;
        }

        /// Receive (and deserialize) group elements from the domain separator.
        ///
        /// The implementation of this trait **MUST** ensure that the points decoded are
        /// valid group elements.
        pub trait GroupToUnitDeserialize<G: $Group + Default> {
            /// Deserialize group elements from the protocol transcript into `output`.
            fn fill_next_points(&mut self, output: &mut [G]) -> $crate::ProofResult<()>;

            /// Deserialize group elements from the protocol transcript and return them.
            fn next_points<const N: usize>(&mut self) -> $crate::ProofResult<[G; N]> {
                let mut output = [G::default(); N];
                self.fill_next_points(&mut output)?;
                Ok(output)
            }
        }

        /// Add group elements to the protocol transcript.
        pub trait CommonGroupToUnit<G: $Group> {
            /// In order to be added to the sponge, elements may be serialize into another format.
            /// This associated type represents the format used, so that other implementation can potentially
            /// re-use the serialized element.
            type Repr;

            /// Incorporate group elements into the proof without adding them to the final protocol transcript.
            fn public_points(&mut self, input: &[G]) -> $crate::ProofResult<Self::Repr>;
        }
    };
}

#[cfg(any(feature = "zkcrypto-group", feature = "arkworks-algebra"))]
pub(super) use {field_traits, group_traits};
