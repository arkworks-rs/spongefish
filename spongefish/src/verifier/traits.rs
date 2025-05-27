use std::{array::from_fn, iter::repeat_with};

use crate::{
    transcript::{Label, Transcript},
    Unit,
};

pub trait Verifier<'a, U>: Transcript
where
    U: Unit,
{
    fn ratchet(&mut self) -> Result<(), Self::Error>;

    fn message_unit_out(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &mut U,
    ) -> Result<(), Self::Error>;

    fn message_unit(&mut self, label: impl Into<Label>) -> Result<U, Self::Error>
    where
        U: Default,
    {
        let mut result = U::default();
        self.message_unit_out(label, &mut result)?;
        Ok(result)
    }

    fn message_units_out(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &mut [U],
    ) -> Result<(), Self::Error>;

    fn message_units_array<const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[U; N], Self::Error>
    where
        U: Default,
    {
        let mut result = from_fn(|_| U::default());
        self.message_units_out(label, &mut result)?;
        Ok(result)
    }

    fn message_units_vec<const N: usize>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<U>, Self::Error>
    where
        U: Default,
    {
        let mut result = repeat_with(|| U::default()).take(size).collect::<Vec<_>>();
        self.message_units_out(label, &mut result)?;
        Ok(result)
    }

    fn challenge_unit_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut U,
    ) -> Result<(), Self::Error>;

    fn challenge_unit(&mut self, label: impl Into<Label>) -> Result<U, Self::Error>
    where
        U: Default,
    {
        let mut result = U::default();
        self.challenge_unit_out(label, &mut result)?;
        Ok(result)
    }

    fn challenge_units_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [U],
    ) -> Result<(), Self::Error>;

    fn challenge_units_array<const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[U; N], Self::Error>
    where
        U: Default,
    {
        let mut result = from_fn(|_| U::default());
        self.challenge_units_out(label, &mut result)?;
        Ok(result)
    }

    fn challenge_units_vec<const N: usize>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<U>, Self::Error>
    where
        U: Default,
    {
        let mut result = repeat_with(|| U::default()).take(size).collect::<Vec<_>>();
        self.challenge_units_out(label, &mut result)?;
        Ok(result)
    }

    fn hint_bytes(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        size: usize,
    ) -> Result<&'a [u8], Self::Error>;

    fn hint_bytes_dynamic(
        &mut self,
        label: impl Into<crate::transcript::Label>,
    ) -> Result<&'a [u8], Self::Error>;
}
