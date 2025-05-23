use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{
    traits::{
        BytesChallenge, BytesHintProver, BytesHintVerifier, BytesMessageProver,
        BytesMessageVerifier, BytesPattern,
    },
    transcript::{Transcript, TranscriptExt as _},
};

pub trait ZeroCopyPattern<T>: Transcript {
    fn message(&mut self, label: &'static str) -> Result<(), Self::Error>;
    fn hint(&mut self, label: &'static str) -> Result<(), Self::Error>;
    fn challenge(&mut self, label: &'static str) -> Result<(), Self::Error>;
}

pub trait ZeroCopyMessageProver<T: Immutable + IntoBytes>: Transcript {
    fn message(&mut self, label: &'static str, value: &T) -> Result<(), Self::Error>;
}

pub trait ZeroCopyMessageVerifier<T: IntoBytes + FromBytes>: Transcript {
    fn message(&mut self, label: &'static str) -> Result<T, Self::Error>;
}

pub trait ZeroCopyHintProver<T: Immutable + IntoBytes>: Transcript {
    fn hint(&mut self, label: &'static str, value: &T) -> Result<(), Self::Error>;
}

pub trait ZeroCopyHintVerifier<T: IntoBytes + FromBytes>: Transcript {
    fn hint(&mut self, label: &'static str) -> Result<T, Self::Error>;
}

pub trait ZeroCopyChallenge<T: IntoBytes + FromBytes>: Transcript {
    fn challenge(&mut self, label: &'static str) -> Result<T, Self::Error>;
}

impl<State, T> ZeroCopyPattern<T> for State
where
    State: Transcript + BytesPattern,
{
    fn message(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.begin_message::<(Self, T)>(label)?;
        self.add_bytes(size_of::<T>(), label);
        self.end_message::<(Self, T)>(label)
    }

    fn hint(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.begin_hint::<(Self, T)>(label)?;
        self.hint(label);
        self.end_hint::<(Self, T)>(label)
    }

    fn challenge(&mut self, label: &'static str) -> Result<(), Self::Error> {
        self.begin_challenge::<(Self, T)>(label)?;
        self.challenge_bytes(size_of::<T>(), label);
        self.end_challenge::<(Self, T)>(label)
    }
}

impl<State, T> ZeroCopyMessageProver<T> for State
where
    State: Transcript + BytesMessageProver,
    T: Immutable + IntoBytes,
{
    fn message(&mut self, label: &'static str, value: &T) -> Result<(), Self::Error> {
        self.begin_message::<(Self, T)>(label)?;
        self.message(value.as_bytes()).unwrap();
        self.end_message::<(Self, T)>(label)
    }
}

impl<State, T> ZeroCopyMessageVerifier<T> for State
where
    State: Transcript + BytesMessageVerifier,
    T: IntoBytes + FromBytes,
{
    fn message(&mut self, label: &'static str) -> Result<T, Self::Error> {
        self.begin_message::<(Self, T)>(label)?;
        let mut result = T::new_zeroed();
        self.message(result.as_mut_bytes()).unwrap();
        self.end_message::<(Self, T)>(label)?;
        Ok(result)
    }
}

impl<State, T> ZeroCopyHintProver<T> for State
where
    State: Transcript + BytesHintProver,
    T: Immutable + IntoBytes,
{
    fn hint(&mut self, label: &'static str, value: &T) -> Result<(), Self::Error> {
        self.begin_hint::<(Self, T)>(label)?;
        self.hint(value.as_bytes()).unwrap();
        self.end_hint::<(Self, T)>(label)
    }
}

impl<State, T> ZeroCopyHintVerifier<T> for State
where
    State: Transcript + BytesHintVerifier,
    T: FromBytes + IntoBytes,
{
    fn hint(&mut self, label: &'static str) -> Result<T, Self::Error> {
        self.begin_message::<(Self, T)>(label)?;
        let mut result = T::new_zeroed();
        self.hint(result.as_mut_bytes()).unwrap();
        self.end_message::<(Self, T)>(label)?;
        Ok(result)
    }
}

impl<State, T> ZeroCopyChallenge<T> for State
where
    State: Transcript + BytesChallenge,
    T: FromBytes + IntoBytes,
{
    fn challenge(&mut self, label: &'static str) -> Result<T, Self::Error> {
        self.begin_challenge::<(Self, T)>(label)?;
        let mut result = T::new_zeroed();
        self.challenge(result.as_mut_bytes()).unwrap();
        self.end_challenge::<(Self, T)>(label)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
