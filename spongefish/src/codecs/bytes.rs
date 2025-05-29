//! Traits that convert between byte arrays and units.
use crate::{
    transcript::{Label, Length},
    Unit, UnitCommon, UnitPattern, UnitProver, UnitVerifier,
};

/// Traits for patterns that handle byte arrays in a transcript.
pub trait BytesPattern<U>: UnitPattern<U>
where
    U: Unit,
{
    fn public_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn message_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn challenge_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
}

/// Traits for prover/verifier common byte operations in a transcript.
pub trait BytesCommon<U>: UnitCommon<U>
where
    U: Unit,
{
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

    fn challenge_bytes_vec<const N: usize>(
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
pub trait BytesProver<U>: UnitProver<U> + BytesCommon<U>
where
    U: Unit,
{
    fn message_bytes(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error>;
}

/// Verifier trait for handling byte arrays in a transcript.
pub trait BytesVerifier<'a, U>: UnitVerifier<'a, U> + BytesCommon<U>
where
    U: Unit,
{
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

    fn message_bytes_vec<const N: usize>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut result = vec![0; size];
        self.message_bytes_out(label, &mut result)?;
        Ok(result)
    }
}

/// Default implementation of [`BytesPattern`] when the native unit is `u8`.
impl<P> BytesPattern<u8> for P
where
    P: UnitPattern<u8>,
{
    fn public_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_public::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.public_units("bytes-prover-u8", size)?;
        self.end_public::<[u8]>(label, Length::Fixed(size))
    }

    fn message_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.message_units("bytes-prover-u8", size)?;
        self.end_message::<[u8]>(label, Length::Fixed(size))
    }

    fn challenge_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_challenge::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.challenge_units("bytes-prover-u8", size)?;
        self.end_challenge::<[u8]>(label, Length::Fixed(size))
    }
}

/// Default implementation of [`BytesCommon`] when the native unit is `u8`.
impl<P> BytesCommon<u8> for P
where
    P: UnitCommon<u8>,
{
    fn public_bytes(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_public::<[u8]>(label.clone(), Length::Fixed(value.len()))?;
        self.public_units("bytes-prover-u8", value)?;
        self.end_public::<[u8]>(label, Length::Fixed(value.len()))
    }

    fn challenge_bytes_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [u8],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_challenge::<[u8]>(label.clone(), Length::Fixed(out.len()))?;
        self.challenge_units_out("bytes-prover-u8", out)?;
        self.end_challenge::<[u8]>(label, Length::Fixed(out.len()))
    }
}

/// Default implementation of [`BytesProver`] when the native unit is `u8`.
impl<P> BytesProver<u8> for P
where
    P: UnitProver<u8>,
{
    fn message_bytes(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(value.len()))?;
        self.message_units("bytes-prover-u8", value)?;
        self.end_message::<[u8]>(label, Length::Fixed(value.len()))
    }
}

/// Default implementation of [`BytesVerifier`] when the native unit is `u8`.
impl<'a, P> BytesVerifier<'a, u8> for P
where
    P: UnitVerifier<'a, u8>,
{
    fn message_bytes_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [u8],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(out.len()))?;
        self.message_units_out("bytes-prover-u8", out)?;
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
        assert_eq!(prover.challenge_bytes_array("3")?, [172, 209, 100, 74]);
        prover.end_protocol::<()>("test all")?;
        let proof = prover.finalize()?;

        assert_eq!(hex::encode(&proof), "02000000");

        let mut verifier: VerifierState = VerifierState::new(pattern.into(), &proof);
        verifier.begin_protocol::<()>("test all")?;
        verifier.public_bytes("1", &1_u32.to_le_bytes())?;
        assert_eq!(verifier.message_bytes_array("2")?, 2_u32.to_le_bytes());
        assert_eq!(verifier.challenge_bytes_array("3")?, [172, 209, 100, 74]);
        verifier.end_protocol::<()>("test all")?;
        verifier.finalize()?;

        Ok(())
    }
}
