use std::{array::from_fn, iter::repeat_with};

use crate::{
    transcript::{Label, Transcript},
    Unit,
};

pub trait UnitPattern<U>: Transcript
where
    U: Unit,
{
    fn ratchet(&mut self) -> Result<(), Self::Error>;
    fn public_unit(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
    fn public_units(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn message_unit(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
    fn message_units(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn challenge_unit(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
    fn challenge_units(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn hint_bytes(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn hint_bytes_dynamic(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
}

pub trait UnitCommon<U>: Transcript
where
    U: Unit,
{
    fn public_unit(&mut self, label: impl Into<Label>, value: &U) -> Result<(), Self::Error>;

    fn public_units(&mut self, label: impl Into<Label>, value: &[U]) -> Result<(), Self::Error>;

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
}

pub trait UnitProver<U>: UnitCommon<U>
where
    U: Unit,
{
    /// Return a reference to the random number generator associated to the protocol transcript.
    ///
    /// ```
    /// # use spongefish::*;
    /// # use rand::RngCore;
    ///
    /// // The domain separator does not need to specify the private coins.
    /// let domain_separator = DomainSeparator::<DefaultHash>::new("📝");
    /// let mut prover_state = domain_separator.to_prover_state();
    /// assert_ne!(prover_state.rng().next_u32(), 0, "You won the lottery!");
    /// let mut challenges = [0u8; 32];
    /// prover_state.rng().fill_bytes(&mut challenges);
    /// assert_ne!(challenges, [0u8; 32]);
    /// ```
    #[cfg(not(feature = "arkworks-rand"))]
    fn rng(&mut self) -> impl rand::CryptoRng;

    /// Return a reference to the random number generator associated to the protocol transcript.
    ///
    /// ```
    /// # use spongefish::*;
    /// # use rand::RngCore;
    ///
    /// // The domain separator does not need to specify the private coins.
    /// let domain_separator = DomainSeparator::<DefaultHash>::new("📝");
    /// let mut prover_state = domain_separator.to_prover_state();
    /// assert_ne!(prover_state.rng().next_u32(), 0, "You won the lottery!");
    /// let mut challenges = [0u8; 32];
    /// prover_state.rng().fill_bytes(&mut challenges);
    /// assert_ne!(challenges, [0u8; 32]);
    /// ```
    #[cfg(feature = "arkworks-rand")]
    fn rng(&mut self) -> impl rand::CryptoRng + ark_std::rand::CryptoRng;

    /// Ratchet the prover's state.
    fn ratchet(&mut self) -> Result<(), Self::Error>;

    fn message_unit(&mut self, label: impl Into<Label>, value: &U) -> Result<(), Self::Error>;

    fn message_units(&mut self, label: impl Into<Label>, value: &[U]) -> Result<(), Self::Error>;

    fn hint_bytes(&mut self, label: impl Into<Label>, value: &[u8]) -> Result<(), Self::Error>;

    fn hint_bytes_dynamic(
        &mut self,
        label: impl Into<Label>,
        value: &[u8],
    ) -> Result<(), Self::Error>;
}

pub trait UnitVerifier<'a, U>: UnitCommon<U>
where
    U: Unit,
{
    fn ratchet(&mut self) -> Result<(), Self::Error>;

    fn message_unit_out(
        &mut self,
        label: impl Into<Label>,
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
        label: impl Into<Label>,
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

    fn hint_bytes(&mut self, label: impl Into<Label>, size: usize)
        -> Result<&'a [u8], Self::Error>;

    fn hint_bytes_dynamic(&mut self, label: impl Into<Label>) -> Result<&'a [u8], Self::Error>;
}
