//! [`zerocopy`] allows safe and efficient conversion to/from bytes for types that have
//! simple in-memory representations.

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use super::bytes::BytesProver;
use crate::{
    prover::Prover,
    transcript::{Label, Length},
    verifier::Verifier,
    Unit,
};

pub trait ZeroCopyProver<U, T>: Prover<U>
where
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn message_zerocopy(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>;

    fn message_zerocopy_slice(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>;

    fn challenge_zerocopy_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>;

    fn challenge_zerocopy(&mut self, label: impl Into<Label>) -> Result<T, Self::Error>
    where
        T: FromZeros,
    {
        let mut result = T::new_zeroed();
        self.challenge_zerocopy_out(label, &mut result)?;
        Ok(result)
    }

    fn challenge_zerocopy_slice_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>;

    fn challenge_zerocopy_array<const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[T; N], Self::Error>
    where
        T: FromZeros,
    {
        let mut result = <[T; N]>::new_zeroed();
        self.challenge_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    fn challenge_zerocopy_vec(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<T>, Self::Error>
    where
        T: FromZeros,
    {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.challenge_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }
}

pub trait ZeroCopyVerifier<'a, U, T>: Verifier<'a, U>
where
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn message_zerocopy_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>;

    fn message_zerocopy_slice_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>;

    fn challenge_zerocopy_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>;

    fn challenge_zerocopy_slice_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>;
}

pub trait ZeroCopyHintProver<U, T>: Prover<U>
where
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn hint_zerocopy(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>;

    fn hint_zerocopy_dynamic(
        &mut self,
        label: impl Into<Label>,
        value: &T,
    ) -> Result<(), Self::Error>;
}

pub trait ZeroCopyHintVerifier<U, T>: Prover<U>
where
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn hint_zerocopy(&mut self, label: impl Into<Label>, out: &mut T) -> Result<(), Self::Error>;

    fn hint_zerocopy_dynamic(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>;
}

impl<P, U, T> ZeroCopyProver<U, T> for P
where
    P: BytesProver<U>,
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn message_zerocopy(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Scalar)?;
        self.message_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_message::<T>(label, Length::Scalar)
    }

    fn message_zerocopy_slice(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Fixed(value.len()))?;
        self.message_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_message::<T>(label, Length::Fixed(value.len()))
    }

    fn challenge_zerocopy_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_challenge::<T>(label.clone(), Length::Scalar)?;
        self.challenge_bytes_out("zerocopy-bytes", out.as_mut_bytes())?;
        self.end_challenge::<T>(label, Length::Scalar)
    }

    fn challenge_zerocopy_slice_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_challenge::<T>(label.clone(), Length::Fixed(out.len()))?;
        self.challenge_bytes_out("zerocopy-bytes", out.as_mut_bytes())?;
        self.end_challenge::<T>(label, Length::Fixed(out.len()))
    }
}

impl<P, U, T> ZeroCopyHintProver<U, T> for P
where
    P: Prover<U>,
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn hint_zerocopy(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        self.hint_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_hint::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }

    fn hint_zerocopy_dynamic(
        &mut self,
        label: impl Into<Label>,
        value: &T,
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Dynamic)?;
        self.hint_bytes_dynamic("zerocopy-bytes-dynamic", value.as_bytes())?;
        self.end_hint::<T>(label.clone(), Length::Dynamic)?;
        Ok(())
    }
}
