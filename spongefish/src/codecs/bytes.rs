//! Traits that convert between byte arrays and units.
use std::borrow::Cow;

use crate::{
    codecs::unit,
    transcript::{Label, Length},
    Unit,
};

/// Rust allows only one generalized implementation (i.e. `impl<T> Trait for T where `), so to
/// get dispatch on the Unit type we need to define a trait that on the Unit itself.
///
/// Alternatively we could dispatch on the concrete type `ProverState<U>`, but that would
/// require exposing more functionality in the `ProverState` type directly. Doing it via a trait
/// on Unit also deduplicates more of the implementation.
pub trait UnitBytes: Sized + Default
where
    [Self]: ToOwned,
{
    // Units required to unambiguously represent `bytes` bytes.
    fn pack_units_required(bytes: usize) -> usize;

    // Units required to deterministically extract `bytes` bytes that are within 2^-128 of uniformly
    // random.
    fn random_units_required(bytes: usize) -> usize;

    fn pack_bytes<'a>(bytes: &'a [u8]) -> Cow<'a, [Self]>;
    fn unpack_bytes(units: &[Self], out: &mut [u8]);
    fn random_bytes(units: &[Self], out: &mut [u8]);
}

/// Traits for patterns that handle byte arrays in a transcript.
pub trait Pattern: unit::Pattern {
    fn public_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn message_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn challenge_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
}

/// Traits for prover/verifier common byte operations in a transcript.
pub trait Common: unit::Common {
    fn public_bytes(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error>;

    fn challenge_bytes_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [u8],
    ) -> Result<(), Self::Error>;

    fn challenge_bytes_array<const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[u8; N], Self::Error> {
        let mut result = [0; N];
        self.challenge_bytes_out(label, &mut result)?;
        Ok(result)
    }

    fn challenge_bytes_vec(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut result = vec![0; size];
        self.challenge_bytes_out(label, &mut result)?;
        Ok(result)
    }
}

/// Prover trait for handling byte arrays in a transcript.
pub trait Prover: unit::Prover + Common {
    fn message_bytes(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error>;
}

/// Verifier trait for handling byte arrays in a transcript.
pub trait Verifier<'a>: unit::Verifier<'a> + Common {
    fn message_bytes_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [u8],
    ) -> Result<(), Self::Error>;

    fn message_bytes_array<const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[u8; N], Self::Error> {
        let mut result = [0; N];
        self.message_bytes_out(label, &mut result)?;
        Ok(result)
    }

    fn message_bytes_vec(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut result = vec![0; size];
        self.message_bytes_out(label, &mut result)?;
        Ok(result)
    }
}

/// Trivial implementation of [`UnitBytes`] for `u8`.
impl UnitBytes for u8 {
    fn pack_units_required(bytes: usize) -> usize {
        bytes
    }

    fn random_units_required(bytes: usize) -> usize {
        bytes
    }

    fn pack_bytes<'a>(bytes: &'a [u8]) -> Cow<'a, [Self]> {
        Cow::Borrowed(bytes)
    }

    fn unpack_bytes(units: &[Self], out: &mut [u8]) {
        out.copy_from_slice(units);
    }

    fn random_bytes(units: &[Self], out: &mut [u8]) {
        out.copy_from_slice(units);
    }
}

impl<P> Pattern for P
where
    P: unit::Pattern,
    P::Unit: UnitBytes,
{
    fn public_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_public::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.public_units("bytes", P::Unit::pack_units_required(size))?;
        self.end_public::<[u8]>(label, Length::Fixed(size))
    }

    fn message_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.message_units("bytes", P::Unit::pack_units_required(size))?;
        self.end_message::<[u8]>(label, Length::Fixed(size))
    }

    fn challenge_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_challenge::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.challenge_units("bytes", P::Unit::random_units_required(size))?;
        self.end_challenge::<[u8]>(label, Length::Fixed(size))
    }
}

impl<P> Common for P
where
    P: unit::Common,
    P::Unit: UnitBytes,
{
    fn public_bytes(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_public::<[u8]>(label.clone(), Length::Fixed(value.len()))?;
        let value = P::Unit::pack_bytes(value);
        self.public_units("bytes", &value)?;
        self.end_public::<[u8]>(label, Length::Fixed(value.len()))
    }

    fn challenge_bytes_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [u8],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_challenge::<[u8]>(label.clone(), Length::Fixed(out.len()))?;
        let units_required = P::Unit::random_units_required(out.len());
        let units = self.challenge_units_vec("bytes", units_required)?;
        P::Unit::random_bytes(&units, out);
        self.end_challenge::<[u8]>(label, Length::Fixed(out.len()))
    }
}

impl<P> Prover for P
where
    P: unit::Prover,
    P::Unit: UnitBytes,
{
    fn message_bytes(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(value.len()))?;
        let value = P::Unit::pack_bytes(value);
        self.message_units("bytes", &value)?;
        self.end_message::<[u8]>(label, Length::Fixed(value.len()))
    }
}

impl<'a, P> Verifier<'a> for P
where
    P: unit::Verifier<'a>,
    P::Unit: UnitBytes,
{
    fn message_bytes_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [u8],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(out.len()))?;
        let units_required = P::Unit::pack_units_required(out.len());
        let units = self.message_units_vec("bytes", units_required)?;
        P::Unit::unpack_bytes(&units, out);
        self.end_message::<[u8]>(label, Length::Fixed(out.len()))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use crate::{
        transcript::{Transcript, TranscriptRecorder},
        ProverState, VerifierState,
    };

    #[test]
    fn test_all_ops() -> Result<(), Box<dyn Error>> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.begin_protocol::<()>("test all")?;
        pattern.public_bytes("1", 4)?;
        pattern.message_bytes("2", 4)?;
        pattern.challenge_bytes("3", 4)?;
        pattern.end_protocol::<()>("test all")?;
        let pattern = pattern.finalize()?;

        let mut prover: ProverState = ProverState::from(&pattern);
        prover.begin_protocol::<()>("test all")?;
        prover.public_bytes("1", &1_u32.to_le_bytes())?;
        prover.message_bytes("2", &2_u32.to_le_bytes())?;
        assert_eq!(prover.challenge_bytes_array("3")?, [248, 244, 92, 189]);
        prover.end_protocol::<()>("test all")?;
        let proof = prover.finalize()?;

        assert_eq!(hex::encode(&proof), "02000000");

        let mut verifier: VerifierState = VerifierState::new(pattern.into(), &proof);
        verifier.begin_protocol::<()>("test all")?;
        verifier.public_bytes("1", &1_u32.to_le_bytes())?;
        assert_eq!(verifier.message_bytes_array("2")?, 2_u32.to_le_bytes());
        assert_eq!(verifier.challenge_bytes_array("3")?, [248, 244, 92, 189]);
        verifier.end_protocol::<()>("test all")?;
        verifier.finalize()?;

        Ok(())
    }
}
