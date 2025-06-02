//! Use ark_serialize to convert types to/from bytes.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
use thiserror::Error;

use crate::{
    codecs::{bytes, unit},
    transcript::{InteractionError, Label, Length},
    Unit,
};

#[derive(Debug, Error)]
pub enum Error<E> {
    #[error(transparent)]
    Inner(#[from] E),
    #[error("Serialization error: {0}")]
    Serialization(SerializationError),
}

pub trait ArkworksHintPattern<U>: unit::Pattern<U>
where
    U: Unit,
{
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksHintProver<U>: unit::Prover<U>
where
    U: Unit,
{
    fn hint_arkworks<T>(
        &mut self,
        label: impl Into<Label>,
        value: &T,
    ) -> Result<(), Error<Self::Error>>
    where
        T: CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksHintVerifier<'a, U>: unit::Verifier<'a, U>
where
    U: Unit,
{
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<T, Error<Self::Error>>
    where
        T: CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksPattern<U>: unit::Pattern<U>
where
    U: Unit,
{
    fn public_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize;

    fn message_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksCommon<U>: unit::Common<U>
where
    U: Unit,
{
    fn public_arkworks<T>(
        &mut self,
        label: impl Into<Label>,
        value: &T,
    ) -> Result<(), Error<Self::Error>>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksProver<U>: unit::Prover<U>
where
    U: Unit,
{
    fn message_arkworks<T>(
        &mut self,
        label: impl Into<Label>,
        value: &T,
    ) -> Result<(), Error<Self::Error>>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksVerifier<'a, U>: unit::Verifier<'a, U>
where
    U: Unit,
{
    fn message_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<T, Error<Self::Error>>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize;
}

impl<U, P> ArkworksHintPattern<U> for P
where
    U: Unit,
    P: unit::Pattern<U>,
{
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
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

impl<U, P> ArkworksHintProver<U> for P
where
    U: Unit,
    P: unit::Prover<U, Error = InteractionError>,
{
    fn hint_arkworks<T>(
        &mut self,
        label: impl Into<Label>,
        value: &T,
    ) -> Result<(), Error<Self::Error>>
    where
        T: CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        let size = value.serialized_size(Compress::Yes);
        let mut buffer = Vec::with_capacity(size);
        value
            .serialize_compressed(&mut buffer)
            .map_err(Error::Serialization)?;
        self.hint_bytes_dynamic("arkworks-bytes", &buffer)?;
        self.end_hint::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }
}

impl<'a, U, P> ArkworksHintVerifier<'a, U> for P
where
    U: Unit,
    P: unit::Verifier<'a, U>,
{
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<T, Error<Self::Error>>
    where
        T: CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        let slice = self.hint_bytes_dynamic("arkworks-bytes")?;
        let value = T::deserialize_compressed(slice).map_err(Error::Serialization)?;
        self.end_hint::<T>(label.clone(), Length::Scalar)?;
        Ok(value)
    }
}

impl<U, P> ArkworksPattern<U> for P
where
    U: Unit,
    P: bytes::Pattern<U>,
{
    fn public_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        let size = T::default().compressed_size();
        self.begin_public::<T>(label.clone(), Length::Scalar)?;
        self.public_bytes("arkworks-bytes", size)?;
        self.end_public::<T>(label, Length::Scalar)
    }

    fn message_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
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

impl<U, P> ArkworksCommon<U> for P
where
    U: Unit,
    P: bytes::Common<U>,
{
    fn public_arkworks<T>(
        &mut self,
        label: impl Into<Label>,
        value: &T,
    ) -> Result<(), Error<Self::Error>>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_public::<T>(label.clone(), Length::Scalar)?;
        let size = value.compressed_size();
        let mut buffer = Vec::with_capacity(size);
        value
            .serialize_compressed(&mut buffer)
            .map_err(Error::Serialization)?;
        self.public_bytes("arkworks-bytes", &buffer)?;
        self.end_public::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }
}

impl<U, P> ArkworksProver<U> for P
where
    U: Unit,
    P: bytes::Prover<U>,
{
    fn message_arkworks<T>(
        &mut self,
        label: impl Into<Label>,
        value: &T,
    ) -> Result<(), Error<Self::Error>>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Scalar)?;
        let size = value.serialized_size(Compress::Yes);
        let mut buffer = Vec::with_capacity(size);
        value
            .serialize_compressed(&mut buffer)
            .map_err(Error::Serialization)?;
        self.message_bytes("arkworks-bytes", &buffer)?;
        self.end_message::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }
}

impl<'a, U, P> ArkworksVerifier<'a, U> for P
where
    U: Unit,
    P: bytes::Verifier<'a, U>,
{
    fn message_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<T, Error<Self::Error>>
    where
        T: Default + CanonicalSerialize + CanonicalDeserialize,
    {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Scalar)?;
        let size = T::default().serialized_size(Compress::Yes);
        let bytes = self.message_bytes_vec("arkworks-bytes", size)?;
        let mut reader = bytes.as_slice();
        let value = T::deserialize_compressed(&mut reader).map_err(Error::Serialization)?;
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

        let mut verifier = TestVerifier::new(pattern.into(), &proof);
        verifier.public_arkworks("1", &1_u64)?;
        assert_eq!(verifier.message_arkworks::<u64>("2")?, 2);
        assert_eq!(verifier.hint_arkworks::<String>("3")?, "Hello");
        verifier.finalize()?;

        Ok(())
    }
}
