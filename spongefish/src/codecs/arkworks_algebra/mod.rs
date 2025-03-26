//! This module contains utilities for working with [arkworks](https://arkworks.rs) types
//! and aid in the Fiat-Shamir transformation for protocols dealing with
//! field elements and group elements.
//!
//! # Examples
//!
//! Here's a protocol that does Fiat-Shamir without caring about the hash function used
//! or the serialization format.
//!
//! ```rust
//! use ark_ec::CurveGroup;
//! use ark_std::UniformRand;
//! use spongefish::{DomainSeparator, ProverState, DuplexSpongeInterface, ProofResult};
//! use spongefish::codecs::arkworks_algebra::*;
//!
//! fn prove<G: CurveGroup>(
//!     prover_state: &mut ProverState,
//!     x: G::ScalarField,
//! ) -> ProofResult<&[u8]>
//! {
//!     let k = G::ScalarField::rand(prover_state.rng());
//!     prover_state.add_points(&[G::generator() * k])?;
//!     let [c]: [G::ScalarField; 1] = prover_state.challenge_scalars()?;
//!     prover_state.add_scalars(&[k + c * x])?;
//!     Ok(prover_state.narg_string())
//! }
//! ```
//! The type constraint on [`ProverState`][`crate::ProverState`] hints the compiler that we are going to be absorbing elements from the group `G` and squeezing challenges in the scalar field `G::ScalarField`. Similarly, we could have been squeezing out bytes.
//!
//! ```rust
//! # use ark_ec::CurveGroup;
//! # use ark_std::UniformRand;
//! # use ark_ff::PrimeField;
//! # use spongefish::{DomainSeparator, ProverState, DuplexSpongeInterface, ProofResult};
//! # use spongefish::codecs::arkworks_algebra::*;
//!
//! fn prove<G: CurveGroup>(
//!     prover_state: &mut ProverState,
//!     x: G::ScalarField,
//! ) -> ProofResult<&[u8]>
//! where
//!     ProverState: GroupToUnitSerialize<G> + UnitToBytes,
//! {
//!     let k = G::ScalarField::rand(prover_state.rng());
//!     prover_state.add_points(&[G::generator() * k])?;
//!     let c_bytes = prover_state.challenge_bytes::<16>()?;
//!     let c = G::ScalarField::from_le_bytes_mod_order(&c_bytes);
//!     prover_state.add_scalars(&[k + c * x])?;
//!     Ok(prover_state.narg_string())
//! }
//! ```
//!
//! [`ProverState`] is actually more general than this, and can be used with any hash function, over any field.
//! Let's for instance use [`sha2`](https://crates.io/crates/sha2) on the above transcript instead of Keccak.
//!
//! ```rust
//! # use ark_ec::CurveGroup;
//! # use ark_std::UniformRand;
//! # use ark_ff::PrimeField;
//! # use spongefish::{DomainSeparator, ProverState, DuplexSpongeInterface, ProofResult};
//! # use spongefish::codecs::arkworks_algebra::*;
//!
//! fn prove<G: CurveGroup, H: DuplexSpongeInterface>(
//!     prover_state: &mut ProverState<H>,
//!     x: G::ScalarField,
//! ) -> ProofResult<&[u8]>
//! # {
//! #     let k = G::ScalarField::rand(prover_state.rng());
//! #     prover_state.add_points(&[G::generator() * k])?;
//! #     let c_bytes = prover_state.challenge_bytes::<16>()?;
//! #     let c = G::ScalarField::from_le_bytes_mod_order(&c_bytes);
//! #     prover_state.add_scalars(&[k + c * x])?;
//! #     Ok(prover_state.narg_string())
//! # }
//! ```
//! No change to the function body is needed.
//! Now the proving function can be called with [`spongefish::DigestBridge<sha2::Sha256>`][`crate::DigestBridge`].
//! As easy as that.
//! More _modern_ hash functions may want to operate over some some field different than $\mathbb{F}_8$,
//! for instance over the base field of the sponge.
//! Also in this case it's sufficient to slightly change the proving function to specify the field over which the
//! hash function operates, to something like:
//!
//! ```rust
//! # use ark_ec::CurveGroup;
//! # use ark_std::UniformRand;
//! # use ark_ff::{PrimeField, BigInteger};
//! # use spongefish::{DomainSeparator, ProverState, DuplexSpongeInterface, ProofResult};
//! # use spongefish::codecs::arkworks_algebra::*;
//!
//! fn prove<G, H, U>(
//!     prover_state: &mut ProverState<H, U>,
//!     x: G::ScalarField,
//! ) -> ProofResult<&[u8]>
//! where
//!     G: CurveGroup,
//!     G::BaseField: PrimeField,
//!     // Declares the type the hash function works on
//!     U: Unit,
//!     // Constrains the hash function to work over U, ...
//!     H: DuplexSpongeInterface<U>,
//!     // ... and the prover to be able to absorb and squeeze elements from the group and the base field.
//!     // (normally would be the ScalarField but this is to make it work nicely with algebraic hashes)
//!     ProverState<H, U>: GroupToUnitSerialize<G> + FieldToUnitSerialize<G::BaseField> + UnitToBytes,
//! {
//!     let k = G::ScalarField::rand(prover_state.rng());
//!     prover_state.add_points(&[G::generator() * k])?;
//!     let c_bytes = prover_state.challenge_bytes::<16>()?;
//!     let c = G::ScalarField::from_le_bytes_mod_order(&c_bytes);
//!     // XXX. very YOLO code, don't do this at home.
//!     // The resulting proof is malleable and could also not be correct if
//!     // G::BaseField::MODULUS < G::ScalarField::MODULUS
//!     let r = G::BaseField::from_le_bytes_mod_order(&(k + c * x).into_bigint().to_bytes_le());
//!     prover_state.add_scalars(&[r])?;
//!     Ok(prover_state.narg_string())
//! }
//! ```
//! Now the above code should work with algebraic hashes such as `PoseidonHash` just as well as [`Keccak`][`crate::keccak::Keccak`].
//!
/// IO Pattern utilities.
mod domain_separator;
/// Add public elements (field or group elements) to the protocol transcript.
mod verifier_messages;

/// Veririfer's utilities for decoding a transcript.
mod deserialize;
/// Prover's utilities for encoding into a transcript.
mod prover_messages;

/// Tests for arkworks.
#[cfg(test)]
mod tests;

pub use crate::traits::*;
pub use crate::{
    duplex_sponge::Unit, DomainSeparator, DuplexSpongeInterface, HashStateWithInstructions,
    ProofError, ProofResult, ProverState, VerifierState,
};

super::traits::field_traits!(ark_ff::Field);
super::traits::group_traits!(ark_ec::CurveGroup, Scalar: ark_ff::PrimeField);

/// Move a value from prime field F1 to prime field F2.
///
/// Return an error if the element considered mod |F1| is different, when seen as an integer, mod |F2|.
/// This in particular happens when element > |F2|.
pub fn swap_field<F1: ark_ff::PrimeField, F2: ark_ff::PrimeField>(a_f1: F1) -> ProofResult<F2> {
    use ark_ff::BigInteger;
    let a_f2 = F2::from_le_bytes_mod_order(&a_f1.into_bigint().to_bytes_le());
    let a_f1_control = F1::from_le_bytes_mod_order(&a_f2.into_bigint().to_bytes_le());
    (a_f1 == a_f1_control)
        .then_some(a_f2)
        .ok_or(ProofError::SerializationError)
}

// pub trait PairingReader<P: ark_ec::pairing::Pairing>: DeserializeGroup<P::G1> + DeserializeGroup<P::G2>  {
//     fn fill_next_g1_points(&mut self, input: &mut [P::G1]) -> crate::ProofResult<()> {
//         DeserializeGroup::<P::G1>::fill_next_points(self, input)
//     }

//     fn fill_next_g2_points(&mut self, input: &mut [P::G2]) -> crate::ProofResult<()> {
//         DeserializeGroup::<P::G2>::fill_next_points(self, input)
//     }
// }
// pub trait PairingWriter<P: ark_ec::pairing::Pairing> {
//     fn add_g1_points(&mut self, input: &[P::G1]) -> crate::ProofResult<()> {
//         GroupToUnitSerialize::<P::G1>::add_points(self, input)
//     }

//     fn add_g2_points(&mut self, input: &[P::G2]) -> crate::ProofResult<()> {
//         GroupToUnitSerialize::<P::G2>::add_points(self, input)
//     }
// }

// impl<'a, P: ark_ec::pairing::Pairing, H, U> PairingWriter<P> for VerifierState<'a, H, U> where
// U: Unit, H: DuplexSpongeInterface<U>,
// VerifierState<'a, H, U>:  GroupToUnitSerialize<P::G1> + GroupToUnitSerialize<P::G2>  {}
