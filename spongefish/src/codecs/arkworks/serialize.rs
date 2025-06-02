//! Use ark_serialize to convert types to/from bytes.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
use thiserror::Error;

use crate::{
    codecs::{bytes, unit},
    transcript::{self, InteractionError, Label, Length, TranscriptError},
    Unit,
};

#[derive(Debug, Error)]
pub enum ProverError {
    #[error(transparent)]
    Interaction(#[from] InteractionError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),
}

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error(transparent)]
    Interaction(#[from] InteractionError),
    #[error(transparent)]
    Verifier(#[from] crate::verifier_state::VerifierError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),
}

pub trait ArkworksHintPattern {
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), TranscriptError>
    where
        T: CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksHintProver {
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>, value: &T) -> Result<(), ProverError>
    where
        T: CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksHintVerifier {
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<T, VerifierError>
    where
        T: CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksPattern {
    fn public_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), TranscriptError>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize;

    fn message_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), TranscriptError>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksCommon {
    fn public_arkworks<T>(&mut self, label: impl Into<Label>, value: &T) -> Result<(), ProverError>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksProver: ArkworksCommon + ArkworksHintProver {
    fn message_arkworks<T>(
        &mut self,
        label: impl Into<Label>,
        value: &T,
    ) -> Result<(), ProverError>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksVerifier: ArkworksCommon + ArkworksHintVerifier {
    fn message_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<T, VerifierError>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize;
}

impl<P> ArkworksHintPattern for P
where
    P: transcript::Pattern + unit::Pattern,
{
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), TranscriptError>
    where
        T: CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        self.hint_bytes_dynamic("arkworks-bytes")?;
        self.end_hint::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }
}

impl<P> ArkworksHintProver for P
where
    P: transcript::Prover + unit::Prover,
{
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>, value: &T) -> Result<(), ProverError>
    where
        T: CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        let size = value.serialized_size(Compress::Yes);
        let mut buffer = Vec::with_capacity(size);
        value.serialize_compressed(&mut buffer)?;
        self.hint_bytes_dynamic("arkworks-bytes", &buffer)?;
        self.end_hint::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }
}

impl<'a, P> ArkworksHintVerifier for P
where
    P: transcript::Verifier + unit::Verifier<'a>,
{
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<T, VerifierError>
    where
        T: CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        let slice = self.hint_bytes_dynamic("arkworks-bytes")?;
        let value = T::deserialize_compressed(slice)?;
        self.end_hint::<T>(label.clone(), Length::Scalar)?;
        Ok(value)
    }
}

impl<P> ArkworksPattern for P
where
    P: transcript::Pattern + bytes::Pattern,
{
    fn public_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), TranscriptError>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        let size = T::default().compressed_size();
        self.begin_public::<T>(label.clone(), Length::Scalar)?;
        self.public_bytes("arkworks-bytes", size)?;
        self.end_public::<T>(label, Length::Scalar)
    }

    fn message_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), TranscriptError>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        let size = T::default().compressed_size();
        self.begin_message::<T>(label.clone(), Length::Scalar)?;
        self.message_bytes("arkworks-bytes", size)?;
        self.end_message::<T>(label, Length::Scalar)
    }
}

impl<P> ArkworksCommon for P
where
    P: transcript::Common + bytes::Common,
{
    fn public_arkworks<T>(&mut self, label: impl Into<Label>, value: &T) -> Result<(), ProverError>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_public::<T>(label.clone(), Length::Scalar)?;
        let size = value.compressed_size();
        let mut buffer = Vec::with_capacity(size);
        value.serialize_compressed(&mut buffer)?;
        self.public_bytes("arkworks-bytes", &buffer)?;
        self.end_public::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }
}

impl<P> ArkworksProver for P
where
    P: ArkworksCommon + ArkworksHintProver + transcript::Prover + bytes::Prover,
{
    fn message_arkworks<T>(&mut self, label: impl Into<Label>, value: &T) -> Result<(), ProverError>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Scalar)?;
        let size = value.serialized_size(Compress::Yes);
        let mut buffer = Vec::with_capacity(size);
        value.serialize_compressed(&mut buffer)?;
        self.message_bytes("arkworks-bytes", &buffer)?;
        self.end_message::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }
}

impl<P> ArkworksVerifier for P
where
    P: ArkworksCommon + ArkworksHintVerifier + transcript::Verifier + bytes::Verifier,
{
    fn message_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<T, VerifierError>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Scalar)?;
        let size = T::default().serialized_size(Compress::Yes);
        let bytes = self.message_bytes_vec("arkworks-bytes", size)?;
        let mut reader = bytes.as_slice();
        let value = T::deserialize_compressed(&mut reader)?;
        self.end_message::<T>(label.clone(), Length::Scalar)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {

    use super::{
        super::tests::{BabyBear, TestProver, TestVerifier},
        *,
    };
    use crate::{transcript::TranscriptRecorder, ProverState, VerifierState};

    #[test]
    fn test_all_ops() -> anyhow::Result<()> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.public_arkworks::<u64>("1")?;
        pattern.message_arkworks::<u64>("2")?;
        pattern.hint_arkworks::<String>("3")?;
        let pattern = pattern.finalize()?;
        eprintln!("{pattern}");

        let mut prover: ProverState = ProverState::from(&pattern);
        prover.public_arkworks("1", &1_u64)?;
        prover.message_arkworks("2", &2_u64)?;
        prover.hint_arkworks("3", &"Hello".to_string())?;
        let proof = prover.finalize()?;
        assert_eq!(
            hex::encode(&proof),
            "02000000000000000d000000050000000000000048656c6c6f"
        );

        let mut verifier: VerifierState = VerifierState::new(pattern.into(), &proof);
        verifier.public_arkworks("1", &1_u64)?;
        assert_eq!(verifier.message_arkworks::<u64>("2")?, 2);
        assert_eq!(verifier.hint_arkworks::<String>("3")?, "Hello");
        verifier.finalize()?;

        Ok(())
    }

    #[test]
    fn test_all_baby_bear() -> anyhow::Result<()> {
        let mut pattern = TranscriptRecorder::<BabyBear>::new();
        pattern.public_arkworks::<u64>("1")?;
        pattern.message_arkworks::<u64>("2")?;
        pattern.hint_arkworks::<String>("3")?;
        let pattern = pattern.finalize()?;
        eprintln!("{pattern}");

        let mut prover = TestProver::from(&pattern);
        prover.public_arkworks("1", &1_u64)?;
        prover.message_arkworks("2", &2_u64)?;
        prover.hint_arkworks("3", &"Hello".to_string())?;
        let proof = prover.finalize()?;
        assert_eq!(
            hex::encode(&proof),
            "0200000000000000000000000d000000050000000000000048656c6c6f"
        );
        eprintln!("Proof size {}", proof.len());

        let mut verifier = TestVerifier::new(pattern.into(), &proof);
        verifier.public_arkworks("1", &1_u64)?;
        assert_eq!(verifier.message_arkworks::<u64>("2")?, 2);
        assert_eq!(verifier.hint_arkworks::<String>("3")?, "Hello");
        verifier.finalize()?;

        Ok(())
    }
}
