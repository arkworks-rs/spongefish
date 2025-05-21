use zerocopy::{FromBytes, IntoBytes, KnownLayout};

pub trait ZeroCopyPattern {
    pub fn byte_message<T: 'static + IntoBytes>(
        &mut self,
        label: &'static str,
    ) -> Result<(), TranscriptError> {
    }

    pub fn byte_hint<T: 'static + IntoBytes>(
        &mut self,
        label: &'static str,
    ) -> Result<(), TranscriptError> {
    }

    pub fn byte_challenge<T: 'static + IntoBytes>(
        &mut self,
        label: &'static str,
    ) -> Result<(), TranscriptError> {
    }
}

pub trait ZeroCopyProver {}

pub trait ZeroCopyVerifier {}

impl<P: BytePattern> ZeroCopyPattern for Pattern {
    fn byte_message<T: 'static + IntoBytes>(
        &mut self,
        label: &'static str,
    ) -> Result<(), TranscriptError> {
        self.transcript.message::<T>(label)?;
        self.inner.update(|s| s.add_bytes(size_of::<T>(), label));
        Ok(())
    }

    fn byte_challenge<T: 'static + IntoBytes>(
        &mut self,
        label: &'static str,
    ) -> Result<(), TranscriptError> {
        self.transcript.challenge::<T>(label)?;
        self.inner
            .update(|s| s.challenge_bytes(size_of::<T>(), label));
        Ok(())
    }
}

#[derive(Clone, Debug, Error)]
pub enum ProverError {
    #[error(transparent)]
    Interaction(#[from] InteractionError),
    #[error(transparent)]
    Spongefish(#[from] spongefish::DomainSeparatorMismatch),
    #[error("Zerocopy error: {0}")]
    Zerocopy(String),
}

impl<S, D> From<zerocopy::SizeError<S, D>> for ProverError
where
    zerocopy::SizeError<S, D>: Display,
{
    fn from(value: zerocopy::SizeError<S, D>) -> Self {
        ProverError::Zerocopy(value.to_string())
    }
}

impl<C: 'static, S: BytesToUnitSerialize + UnitToBytes> Prover<'_, C, S> {
    pub fn byte_message<T: 'static + IntoBytes + Immutable>(
        &mut self,
        label: &'static str,
        value: &T,
    ) -> Result<(), ProverError> {
        self.transcript.message::<T>(label)?;
        self.inner.add_bytes(value.as_bytes())?;
        Ok(())
    }

    pub fn byte_hint<T: 'static + IntoBytes + Immutable>(
        &mut self,
        label: &'static str,
        value: &T,
    ) -> Result<(), ProverError> {
        self.transcript.message::<T>(label)?;
        self.inner.hint_bytes(value.as_bytes())?;
        Ok(())
    }

    pub fn byte_challenge<T: 'static + IntoBytes + FromBytes>(
        &mut self,
        label: &'static str,
    ) -> Result<T, ProverError> {
        self.transcript.challenge::<T>(label)?;
        let mut result = T::new_zeroed();
        self.inner.fill_challenge_bytes(result.as_mut_bytes())?;
        Ok(result)
    }
}
