use std::{array::from_fn, iter::repeat_with};

use crate::{transcript::Label, verifier_state::VerifierError, Unit};

pub trait Pattern {
    type Unit: Unit;

    fn ratchet(&mut self);
    fn public_unit(&mut self, label: impl Into<Label>);
    fn public_units(&mut self, label: impl Into<Label>, size: usize);
    fn message_unit(&mut self, label: impl Into<Label>);
    fn message_units(&mut self, label: impl Into<Label>, size: usize);
    fn challenge_unit(&mut self, label: impl Into<Label>);
    fn challenge_units(&mut self, label: impl Into<Label>, size: usize);
    fn hint_bytes(&mut self, label: impl Into<Label>, size: usize);
    fn hint_bytes_dynamic(&mut self, label: impl Into<Label>);
}

pub trait Common {
    type Unit: Unit;

    fn public_unit(&mut self, label: impl Into<Label>, value: &Self::Unit);

    fn public_units(&mut self, label: impl Into<Label>, value: &[Self::Unit]);

    fn challenge_unit_out(&mut self, label: impl Into<Label>, out: &mut Self::Unit);

    fn challenge_unit(&mut self, label: impl Into<Label>) -> Self::Unit
    where
        Self::Unit: Default,
    {
        let mut result = Self::Unit::default();
        self.challenge_unit_out(label, &mut result);
        result
    }

    fn challenge_units_out(&mut self, label: impl Into<Label>, out: &mut [Self::Unit]);

    fn challenge_units_array<const N: usize>(&mut self, label: impl Into<Label>) -> [Self::Unit; N]
    where
        Self::Unit: Default,
    {
        let mut result = from_fn(|_| Self::Unit::default());
        self.challenge_units_out(label, &mut result);
        result
    }

    fn challenge_units_vec(&mut self, label: impl Into<Label>, size: usize) -> Vec<Self::Unit>
    where
        Self::Unit: Default,
    {
        let mut result = repeat_with(Self::Unit::default)
            .take(size)
            .collect::<Vec<_>>();
        self.challenge_units_out(label, &mut result);
        result
    }
}

pub trait Prover: Common {
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
    fn ratchet(&mut self);

    fn message_unit(&mut self, label: impl Into<Label>, value: &Self::Unit);

    fn message_units(&mut self, label: impl Into<Label>, value: &[Self::Unit]);

    fn hint_bytes(&mut self, label: impl Into<Label>, value: &[u8]);

    fn hint_bytes_dynamic(&mut self, label: impl Into<Label>, value: &[u8]);
}

pub trait Verifier<'a>: Common {
    fn ratchet(&mut self);

    fn message_unit_out(
        &mut self,
        label: impl Into<Label>,
        value: &mut Self::Unit,
    ) -> Result<(), VerifierError>;

    fn message_unit(&mut self, label: impl Into<Label>) -> Result<Self::Unit, VerifierError>
    where
        Self::Unit: Default,
    {
        let mut result = Self::Unit::default();
        self.message_unit_out(label, &mut result)?;
        Ok(result)
    }

    fn message_units_out(
        &mut self,
        label: impl Into<Label>,
        value: &mut [Self::Unit],
    ) -> Result<(), VerifierError>;

    fn message_units_array<const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[Self::Unit; N], VerifierError>
    where
        Self::Unit: Default,
    {
        let mut result = from_fn(|_| Self::Unit::default());
        self.message_units_out(label, &mut result)?;
        Ok(result)
    }

    fn message_units_vec(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<Self::Unit>, VerifierError>
    where
        Self::Unit: Default,
    {
        let mut result = repeat_with(Self::Unit::default)
            .take(size)
            .collect::<Vec<_>>();
        self.message_units_out(label, &mut result)?;
        Ok(result)
    }

    fn hint_bytes(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<&'a [u8], VerifierError>;

    fn hint_bytes_dynamic(&mut self, label: impl Into<Label>) -> Result<&'a [u8], VerifierError>;
}
