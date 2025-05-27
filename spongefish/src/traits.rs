use std::{array::from_fn, error::Error, marker::PhantomData};

use crate::{
    errors::DomainSeparatorMismatch,
    transcript::{Label, Length},
    Unit,
};

// TODO: Ratchet and PublicMessage

pub trait MessagePattern<T> {
    type Error: Error;

    fn message(&mut self, label: impl Into<Label>, ty: PhantomData<T>) -> Result<(), Self::Error>;
    fn message_sized(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn message_dynamic(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
}

/// Add a slice `[U]` to the protocol transcript.
/// The messages are also internally encoded in the protocol transcript,
/// and used to re-seed the prover's random number generator.
///
/// ```
/// use spongefish::{DomainSeparator, DefaultHash, BytesToUnitSerialize};
///
/// let domain_separator = DomainSeparator::<DefaultHash>::new("📝").absorb(20, "how not to make pasta 🤌");
/// let mut prover_state = domain_separator.to_prover_state();
/// assert!(prover_state.add_units(&[0u8; 20]).is_ok());
/// let result = prover_state.add_units(b"1tbsp every 10 liters");
/// assert!(result.is_err())
/// ```
pub trait MessageProver<T> {
    type Error: Error;

    /// A single message of type T
    fn message(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>;

    /// A fixed size message of type [T]
    fn message_fixed(&mut self, label: impl Into<Label>, value: &[T]) -> Result<(), Self::Error>;

    /// A dynamic sized message of type [T]
    fn message_dynamic(&mut self, label: impl Into<Label>, value: &[T]) -> Result<(), Self::Error>;
}

pub trait MessageVerifier<T: ?Sized> {
    type Error: Error;

    fn message(&mut self, label: impl Into<Label>) -> Result<T, Self::Error>
    where
        T: Sized;

    fn message_mut_ref(&mut self, label: impl Into<Label>, out: &mut T) -> Result<(), Self::Error>;
}

pub trait ChallengePattern<T> {
    type Error: Error;

    fn challenge(&mut self, label: impl Into<Label>, ty: PhantomData<T>)
        -> Result<(), Self::Error>;
    fn challenge_sized(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn challenge_dynamic(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
}

pub trait ChallengeProver<T> {
    type Error: Error;

    /// A single challenge of type T
    fn challenge_out(&mut self, label: impl Into<Label>, out: &mut T) -> Result<(), Self::Error>;

    /// A fixed size challenge of type [T]
    fn challenge_fixed(
        &mut self,
        label: impl Into<Label>,
        value: &mut [T],
    ) -> Result<(), Self::Error>;

    /// A dynamic sized challenge of type [T]
    ///
    /// Dynamic here means that the length was not known at the time of producing pattern, but is
    /// known to both prover and verifier at the point where it is needed (e.g. it derives from
    /// previous interactions).
    fn challenge_dynamic(
        &mut self,
        label: impl Into<Label>,
        value: &mut [T],
    ) -> Result<(), Self::Error>;

    /// A single challenge of type T
    fn challenge(&mut self, label: impl Into<Label>) -> Result<T, Self::Error>
    where
        T: Default,
    {
        let mut result = T::default();
        self.challenge_out(label, &mut result)?;
        Ok(result)
    }

    /// A fixed size challenge of type [T] as [T; N]
    fn challenge_array<const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[T; N], Self::Error>
    where
        T: Default,
    {
        let mut result = from_fn(|_| T::default());
        self.challenge_fixed(label, &mut result)?;
        Ok(result)
    }

    /// A fixed size challenge of type [T] as Vec<T>
    fn challenge_vec(&mut self, label: impl Into<Label>, size: usize) -> Result<Vec<T>, Self::Error>
    where
        T: Default,
    {
        let mut result = (0..size).map(|_| T::default()).collect::<Vec<_>>();
        self.challenge_fixed(label, &mut result)?;
        Ok(result)
    }

    /// A dynamic sized challenge of type [T] as Vec<T>
    fn challenge_dynamic_vec(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<T>, Self::Error>
    where
        T: Default,
    {
        let mut result = (0..size).map(|_| T::default()).collect::<Vec<_>>();
        self.challenge_dynamic(label, &mut result)?;
        Ok(result)
    }
}

pub trait ChallengeVerifier<T: ?Sized> {
    type Error: Error;

    fn message(&mut self, label: impl Into<Label>) -> Result<T, Self::Error>
    where
        T: Sized;

    fn message_mut_ref(&mut self, label: impl Into<Label>, out: &mut T) -> Result<(), Self::Error>;
}

pub trait HintPattern<T> {
    type Error: Error;

    fn hint(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
    fn hint_sized(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error>;
    fn hint_dynamic(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
}

pub trait HintProver<T> {
    type Error: Error;

    /// A single hint of type T
    fn hint(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>;

    /// A fixed size hint of type [T]
    fn hint_fixed(&mut self, label: impl Into<Label>, value: &[T]) -> Result<(), Self::Error>;

    /// A dynamic sized hint of type [T]
    fn hint_dynamic(&mut self, label: impl Into<Label>, value: &[T]) -> Result<(), Self::Error>;
}

pub trait HintVerifier<T: ?Sized> {
    type Error: Error;

    fn hint(&mut self, label: impl Into<Label>) -> Result<T, Self::Error>
    where
        T: Sized;

    fn hint_mut_ref(&mut self, label: impl Into<Label>, out: &mut T) -> Result<(), Self::Error>;
}

/// Absorbing and squeezing native elements from the sponge.
///
/// This trait is typically implemented for [`VerifierState`](crate::VerifierState) and [`ProverState`](crate::ProverState) instances.
/// Implementors of this trait are expected to make sure that the unit type `U` matches
/// the one used by the internal sponge.
pub trait UnitTranscript<U: Unit> {
    fn public_units(&mut self, input: &[U]) -> Result<(), DomainSeparatorMismatch>;

    fn fill_challenge_units(&mut self, output: &mut [U]) -> Result<(), DomainSeparatorMismatch>;
}

/// Absorbing bytes from the sponge, without reading or writing them into the protocol transcript.
///
/// This trait is trivial for byte-oriented sponges, but non-trivial for algebraic hashes.
/// This trait implementation is **not** expected to be streaming-friendly.
///
/// For instance, in the case of algebraic sponges operating over a field $\mathbb{F}_p$, we do not expect
/// the implementation to cache field elements filling $\ceil{\log_2(p)}$ bytes.
pub trait CommonUnitToBytes {
    fn public_bytes(&mut self, input: &[u8]) -> Result<(), DomainSeparatorMismatch>;
}

/// Squeezing bytes from the sponge.
///
/// While this trait is trivial for byte-oriented sponges, it is non-trivial for algebraic hashes.
/// In particular, the implementation of this trait is expected to provide different guarantees between units `u8`
/// and $\mathbb{F}_p$ elements:
/// - `u8` implementations are assumed to be streaming-friendly, that is: `implementor.fill_challenge_bytes(&mut out[..1]); implementor.fill_challenge_bytes(&mut out[1..]);` is expected to be equivalent to `implementor.fill_challenge_bytes(&mut out);`.
/// - $\mathbb{F}_p$ implementations are expected to provide no such guarantee. In addition, we expect the implementation to return bytes that are uniformly distributed. In particular, note that the most significant bytes of a $\mod p$ element are not uniformly distributed. The number of bytes good to be used can be discovered playing with [our scripts](https://github.com/arkworks-rs/spongefish/blob/main/spongefish/scripts/useful_bits_modp.py).
pub trait UnitToBytes {
    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), DomainSeparatorMismatch>;

    fn challenge_bytes<const N: usize>(&mut self) -> Result<[u8; N], DomainSeparatorMismatch> {
        let mut output = [0u8; N];
        self.fill_challenge_bytes(&mut output)?;
        Ok(output)
    }
}

/// A trait for absorbing and squeezing bytes from a sponge.
///
/// While this trait is trivial for byte-oriented sponges, non-algebraic hashes are tricky.
/// We point the curious reader to the documentation of [`CommonUnitToBytes`] and [`UnitToBytes`] for more details.
pub trait ByteTranscript: CommonUnitToBytes + UnitToBytes {}

pub trait BytesToUnitDeserialize {
    fn fill_next_bytes(&mut self, input: &mut [u8]) -> Result<(), DomainSeparatorMismatch>;

    fn next_bytes<const N: usize>(&mut self) -> Result<[u8; N], DomainSeparatorMismatch> {
        let mut input = [0u8; N];
        self.fill_next_bytes(&mut input)?;
        Ok(input)
    }
}

pub trait BytesToUnitSerialize {
    fn add_bytes(&mut self, input: &[u8]) -> Result<(), DomainSeparatorMismatch>;
}

/// Methods for adding bytes to the [`DomainSeparator`](crate::DomainSeparator), properly counting group elements.
pub trait ByteDomainSeparator {
    #[must_use]
    fn add_bytes(self, count: usize, label: &str) -> Self;
    #[must_use]
    fn hint(self, label: &str) -> Self;
    #[must_use]
    fn challenge_bytes(self, count: usize, label: &str) -> Self;
}

impl<T: UnitTranscript<u8>> CommonUnitToBytes for T {
    #[inline]
    fn public_bytes(&mut self, input: &[u8]) -> Result<(), DomainSeparatorMismatch> {
        self.public_units(input)
    }
}

impl<T: UnitTranscript<u8>> UnitToBytes for T {
    #[inline]
    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), DomainSeparatorMismatch> {
        self.fill_challenge_units(output)
    }
}

pub trait BytesPattern {
    fn add_bytes(&mut self, count: usize, label: &str);
    fn hint(&mut self, label: &str);
    fn challenge_bytes(&mut self, count: usize, label: &str);
}

pub trait BytesMessageProver {
    fn message(&mut self, input: &[u8]) -> Result<(), DomainSeparatorMismatch>;
}

pub trait BytesMessageVerifier {
    fn message(&mut self, output: &mut [u8]) -> Result<(), DomainSeparatorMismatch>;
}
pub trait BytesHintProver {
    fn hint(&mut self, input: &[u8]) -> Result<(), DomainSeparatorMismatch>;
}

pub trait BytesHintVerifier {
    fn hint(&mut self, output: &mut [u8]) -> Result<(), DomainSeparatorMismatch>;
}

pub trait BytesChallenge {
    fn challenge(&mut self, output: &mut [u8]) -> Result<(), DomainSeparatorMismatch>;
}
