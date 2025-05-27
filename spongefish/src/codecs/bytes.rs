use crate::{
    prover::Prover,
    transcript::{Label, Length},
    verifier::Verifier,
    Unit,
};

pub trait BytesProver<U>: Prover<U>
where
    U: Unit,
{
    fn message_bytes(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error>;

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

pub trait BytesVerifier<'a, U>: Verifier<'a, U>
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

/// Default implementation of [`BytesProver`] when the native unit is `u8`.
impl<P> BytesProver<u8> for P
where
    P: Prover<u8>,
{
    fn message_bytes(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(value.len()))?;
        self.message_units("bytes-prover-u8", value)?;
        self.end_message::<[u8]>(label, Length::Fixed(value.len()))
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

/// Default implementation of [`BytesVerifier`] when the native unit is `u8`.
impl<'a, P> BytesVerifier<'a, u8> for P
where
    P: Verifier<'a, u8>,
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
