//! Use ark_serialize to convert types to/from bytes.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
use thiserror::Error;

use crate::{
    transcript::{InteractionError, Label, Length},
    Unit, UnitPattern, UnitProver, UnitVerifier,
};

#[derive(Debug, Error)]
pub enum Error<E> {
    #[error(transparent)]
    Inner(#[from] E),
    #[error("Serialization error: {0}")]
    Serialization(SerializationError),
}

pub trait ArkworksHintPattern<U>: UnitPattern<U>
where
    U: Unit,
{
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: CanonicalSerialize + CanonicalDeserialize;
}

pub trait ArkworksHintProver<U>: UnitProver<U>
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

pub trait ArkworksHintVerifier<'a, U>: UnitVerifier<'a, U>
where
    U: Unit,
{
    fn hint_arkworks<T>(&mut self, label: impl Into<Label>) -> Result<T, Error<Self::Error>>
    where
        T: CanonicalSerialize + CanonicalDeserialize;
}

impl<U, P> ArkworksHintPattern<U> for P
where
    U: Unit,
    P: UnitPattern<U>,
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
    P: UnitProver<U, Error = InteractionError>,
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
    P: UnitVerifier<'a, U>,
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

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{transcript::TranscriptRecorder, ProverState, VerifierState};

    #[test]
    fn test_all_ops() -> anyhow::Result<()> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.hint_arkworks::<String>("1")?;
        let pattern = pattern.finalize()?;
        eprintln!("{pattern}");

        let mut prover: ProverState = ProverState::from(&pattern);
        prover.hint_arkworks("1", &"Hello".to_string())?;
        let proof = prover.finalize()?;
        assert_eq!(hex::encode(&proof), "0d000000050000000000000048656c6c6f");

        let mut verifier: VerifierState = VerifierState::new(pattern.into(), &proof);
        assert_eq!(verifier.hint_arkworks::<String>("1")?, "Hello");
        verifier.finalize()?;

        Ok(())
    }
}
