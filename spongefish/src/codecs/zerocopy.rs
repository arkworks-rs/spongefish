//! [`zerocopy`] allows safe and efficient conversion to/from bytes for types that have
//! simple in-memory representations.

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    codecs::bytes,
    transcript::{Label, Length},
    Unit, UnitCommon, UnitPattern, UnitProver, UnitVerifier,
};

pub trait HintPattern<U>: UnitPattern<U>
where
    U: Unit,
{
    fn hint_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        self.hint_bytes("zerocopy-bytes", size_of::<T>())?;
        self.end_hint::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }

    fn hint_zerocopies<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Dynamic)?;
        self.hint_bytes("zerocopy-bytes-dynamic", size * size_of::<T>())?;
        self.end_hint::<T>(label.clone(), Length::Dynamic)
    }

    fn hint_zerocopies_dynamic<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Dynamic)?;
        self.hint_bytes_dynamic("zerocopy-bytes-dynamic")?;
        self.end_hint::<T>(label.clone(), Length::Dynamic)
    }
}

pub trait HintProver<U>: UnitProver<U>
where
    U: Unit,
{
    fn hint_zerocopy<T>(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn hint_zerocopy_slice<T>(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn hint_zerocopy_dynamic<T>(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;
}

pub trait HintVerifier<'a, U>: UnitVerifier<'a, U>
where
    U: Unit,
{
    fn hint_zerocopy_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn hint_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<T, Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let mut result = T::new_zeroed();
        self.hint_zerocopy_out(label, &mut result)?;
        Ok(result)
    }

    /// Return a direct reference to the transcript bytes if [`T`] is an [`Unaligned`] type.
    fn hint_zerocopy_ref<T>(&mut self, label: impl Into<Label>) -> Result<&'a T, Self::Error>
    where
        T: Unaligned + Immutable + KnownLayout + FromBytes + IntoBytes;

    fn hint_zerocopy_slice_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn hint_zerocopy_array<T, const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[T; N], Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let mut result = <[T; N]>::new_zeroed();
        self.hint_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    fn hint_zerocopy_vec<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<T>, Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.hint_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    /// Return a direct reference to the transcript bytes if [`T`] is an [`Unaligned`] type.
    fn hint_zerocopy_slice_ref<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<&'a [T], Self::Error>
    where
        T: Unaligned + Immutable + KnownLayout + FromBytes + IntoBytes;

    fn hint_zerocopy_dynamic_vec<T>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<Vec<T>, Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    /// Return a direct reference to the transcript bytes if [`T`] is an [`Unaligned`] type.
    fn hint_zerocopy_dynamic_slice_ref<T>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<&'a [T], Self::Error>
    where
        T: Unaligned + Immutable + KnownLayout + FromBytes + IntoBytes;
}

pub trait Pattern<U>: HintPattern<U>
where
    U: Unit,
{
    fn public_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn public_zerocopies<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn message_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn message_zerocopies<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn challenge_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn challenge_zerocopies<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;
}

pub trait Common<U>: UnitCommon<U>
where
    U: Unit,
{
    fn public_zerocopy<T>(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn public_zerocopy_slice<T>(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn challenge_zerocopy_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn challenge_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<T, Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let mut result = T::new_zeroed();
        self.challenge_zerocopy_out(label, &mut result)?;
        Ok(result)
    }

    fn challenge_zerocopy_slice_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn challenge_zerocopy_array<T, const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[T; N], Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let mut result = <[T; N]>::new_zeroed();
        self.challenge_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    fn challenge_zerocopy_vec<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<T>, Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.challenge_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }
}

pub trait Prover<U>: UnitProver<U> + Common<U>
where
    U: Unit,
{
    fn message_zerocopy<T>(
        &mut self,
        label: impl Into<Label>,
        value: &T,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn message_zerocopy_slice<T>(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;
}

pub trait Verifier<'a, U>: UnitVerifier<'a, U> + Common<U>
where
    U: Unit,
{
    fn message_zerocopy_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn message_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<T, Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let mut result = T::new_zeroed();
        self.message_zerocopy_out(label, &mut result)?;
        Ok(result)
    }

    fn message_zerocopy_slice_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes;

    fn message_zerocopy_array<T, const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[T; N], Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let mut result = <[T; N]>::new_zeroed();
        self.message_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    fn message_zerocopy_vec<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<T>, Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.message_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }
}

/// Implementation of [`ZeroCopyHintPattern`] for all [`UnitPattern`].
impl<P, U> HintPattern<U> for P
where
    P: UnitPattern<U>,
    U: Unit,
{
    fn hint_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        self.hint_bytes("zerocopy-bytes", size_of::<T>())?;
        self.end_hint::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }

    fn hint_zerocopies<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<[T]>(label.clone(), Length::Fixed(size))?;
        self.hint_bytes("zerocopy-bytes", size * size_of::<T>())?;
        self.end_hint::<[T]>(label.clone(), Length::Fixed(size))
    }

    fn hint_zerocopies_dynamic<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<[T]>(label.clone(), Length::Dynamic)?;
        self.hint_bytes_dynamic("zerocopy-bytes-dynamic")?;
        self.end_hint::<[T]>(label.clone(), Length::Dynamic)
    }
}

impl<P, U> HintProver<U> for P
where
    P: UnitProver<U>,
    U: Unit,
{
    fn hint_zerocopy<T>(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        self.hint_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_hint::<T>(label, Length::Scalar)
    }

    fn hint_zerocopy_slice<T>(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<[T]>(label.clone(), Length::Fixed(value.len()))?;
        self.hint_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_hint::<[T]>(label, Length::Fixed(value.len()))
    }

    fn hint_zerocopy_dynamic<T>(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<[T]>(label.clone(), Length::Dynamic)?;
        self.hint_bytes_dynamic("zerocopy-bytes-dynamic", value.as_bytes())?;
        self.end_hint::<[T]>(label, Length::Dynamic)
    }
}

impl<'a, P, U> HintVerifier<'a, U> for P
where
    P: UnitVerifier<'a, U>,
    U: Unit,
{
    fn hint_zerocopy_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        let bytes = out.as_mut_bytes();
        let slice = self.hint_bytes("zerocopy-bytes", bytes.len())?;
        bytes.copy_from_slice(slice);
        self.end_hint::<T>(label, Length::Scalar)
    }

    fn hint_zerocopy_ref<T>(&mut self, label: impl Into<Label>) -> Result<&'a T, Self::Error>
    where
        T: Unaligned + Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        let slice = self.hint_bytes("zerocopy-bytes", size_of::<T>())?;
        let result = T::ref_from_bytes(slice).map_err(|_| todo!())?;
        self.end_hint::<T>(label, Length::Scalar)?;
        Ok(result)
    }

    fn hint_zerocopy_slice_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<[T]>(label.clone(), Length::Fixed(out.len()))?;
        let bytes = out.as_mut_bytes();
        let slice = self.hint_bytes("zerocopy-bytes", bytes.len())?;
        bytes.copy_from_slice(slice);
        self.end_hint::<[T]>(label, Length::Fixed(out.len()))
    }

    fn hint_zerocopy_slice_ref<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<&'a [T], Self::Error>
    where
        T: Unaligned + Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<[T]>(label.clone(), Length::Fixed(size))?;
        let slice = self.hint_bytes("zerocopy-bytes", size * size_of::<T>())?;
        let result = <[T]>::ref_from_bytes(slice).map_err(|_| todo!())?;
        self.end_hint::<[T]>(label, Length::Fixed(size))?;
        Ok(result)
    }

    fn hint_zerocopy_dynamic_vec<T>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<Vec<T>, Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<[T]>(label.clone(), Length::Dynamic)?;
        let slice = self.hint_bytes_dynamic("zerocopy-bytes-dynamic")?;
        if slice.len() % size_of::<T>() != 0 {
            todo!()
        }
        let mut result =
            T::new_vec_zeroed(slice.len() / size_of::<T>()).expect("allocation failure");
        result.as_mut_bytes().copy_from_slice(slice);
        self.end_hint::<[T]>(label, Length::Dynamic)?;
        Ok(result)
    }

    fn hint_zerocopy_dynamic_slice_ref<T>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<&'a [T], Self::Error>
    where
        T: Unaligned + Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_hint::<[T]>(label.clone(), Length::Dynamic)?;
        let slice = self.hint_bytes_dynamic("zerocopy-bytes-dynamic")?;
        let result = <[T]>::ref_from_bytes(slice).map_err(|_| todo!())?;
        self.end_hint::<[T]>(label, Length::Dynamic)?;
        Ok(result)
    }
}

/// Implementation of [`ZeroCopyPattern`] for [`BytesPattern`].
impl<P, U> Pattern<U> for P
where
    P: bytes::Pattern<U>,
    U: Unit,
{
    fn public_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_public::<T>(label.clone(), Length::Scalar)?;
        self.public_bytes("zerocopy-bytes", size_of::<T>())?;
        self.end_public::<T>(label, Length::Scalar)
    }

    fn public_zerocopies<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_public::<[T]>(label.clone(), Length::Fixed(size))?;
        self.public_bytes("zerocopy-bytes", size * size_of::<T>())?;
        self.end_public::<[T]>(label, Length::Fixed(size))
    }

    fn message_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Scalar)?;
        self.message_bytes("zerocopy-bytes", size_of::<T>())?;
        self.end_message::<T>(label, Length::Scalar)
    }

    fn message_zerocopies<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_message::<[T]>(label.clone(), Length::Fixed(size))?;
        self.message_bytes("zerocopy-bytes", size * size_of::<T>())?;
        self.end_message::<[T]>(label, Length::Fixed(size))
    }

    fn challenge_zerocopy<T>(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_challenge::<T>(label.clone(), Length::Scalar)?;
        self.challenge_bytes("zerocopy-bytes", size_of::<T>())?;
        self.end_challenge::<T>(label, Length::Scalar)
    }

    fn challenge_zerocopies<T>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_challenge::<[T]>(label.clone(), Length::Fixed(size))?;
        self.challenge_bytes("zerocopy-bytes", size * size_of::<T>())?;
        self.end_challenge::<[T]>(label, Length::Fixed(size))
    }
}

/// Implementation of [`ZeroCopyCommon`] for [`BytesCommon`].
impl<P, U> Common<U> for P
where
    P: bytes::Common<U>,
    U: Unit,
{
    fn public_zerocopy<T>(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_public::<T>(label.clone(), Length::Scalar)?;
        self.public_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_public::<T>(label, Length::Scalar)
    }

    fn public_zerocopy_slice<T>(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_public::<[T]>(label.clone(), Length::Fixed(value.len()))?;
        self.public_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_public::<[T]>(label, Length::Fixed(value.len()))
    }

    fn challenge_zerocopy_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_challenge::<T>(label.clone(), Length::Scalar)?;
        self.challenge_bytes_out("zerocopy-bytes", out.as_mut_bytes())?;
        self.end_challenge::<T>(label, Length::Scalar)
    }

    fn challenge_zerocopy_slice_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_challenge::<[T]>(label.clone(), Length::Fixed(out.len()))?;
        self.challenge_bytes_out("zerocopy-bytes", out.as_mut_bytes())?;
        self.end_challenge::<[T]>(label, Length::Fixed(out.len()))
    }
}

/// Implementation of [`ZeroCopyProver`] for  [`BytesProver`]s.
impl<P, U> Prover<U> for P
where
    P: bytes::Prover<U>,
    U: Unit,
{
    fn message_zerocopy<T>(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Scalar)?;
        self.message_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_message::<T>(label, Length::Scalar)
    }

    fn message_zerocopy_slice<T>(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_message::<[T]>(label.clone(), Length::Fixed(value.len()))?;
        self.message_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_message::<[T]>(label, Length::Fixed(value.len()))
    }
}

/// Implementation of [`ZeroCopyVerifier`] for  [`BytesVerifier`]s.
impl<'a, P, U> Verifier<'a, U> for P
where
    P: bytes::Verifier<'a, U>,
    U: Unit,
{
    fn message_zerocopy_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Scalar)?;
        self.message_bytes_out("zerocopy-bytes", out.as_mut_bytes())?;
        self.end_message::<T>(label, Length::Scalar)
    }

    fn message_zerocopy_slice_out<T>(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>
    where
        T: Immutable + KnownLayout + FromBytes + IntoBytes,
    {
        let label = label.into();
        self.begin_message::<[T]>(label.clone(), Length::Fixed(out.len()))?;
        self.message_bytes_out("zerocopy-bytes", out.as_mut_bytes())?;
        self.end_message::<[T]>(label, Length::Fixed(out.len()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        transcript::{Transcript, TranscriptRecorder},
        ProverState, VerifierState,
    };

    #[test]
    fn test_all_ops() -> anyhow::Result<()> {
        let mut pattern = TranscriptRecorder::<u8>::new();
        pattern.begin_protocol::<ProverState>("test all")?;
        pattern.public_zerocopy::<f32>("1")?;
        pattern.public_zerocopies::<f32>("2", 2)?;
        pattern.message_zerocopy::<f32>("3")?;
        pattern.message_zerocopies::<f32>("4", 2)?;
        pattern.challenge_zerocopy::<u32>("5")?;
        pattern.challenge_zerocopies::<u32>("6", 2)?;
        pattern.hint_zerocopy::<u16>("7")?;
        pattern.hint_zerocopies::<u16>("8", 2)?;
        pattern.hint_zerocopies_dynamic::<u16>("9")?;
        pattern.end_protocol::<ProverState>("test all")?;
        let pattern = pattern.finalize()?;
        eprintln!("{pattern}");

        let mut prover: ProverState = ProverState::from(&pattern);
        prover.begin_protocol::<ProverState>("test all")?;
        prover.public_zerocopy::<f32>("1", &1.0)?;
        prover.public_zerocopy_slice::<f32>("2", &[2.0, 3.0])?;
        prover.message_zerocopy("3", &3.0_f32)?;
        prover.message_zerocopy_slice("4", &[4.0_f32, 5.0])?;
        assert_eq!(prover.challenge_zerocopy::<u32>("5")?, 1082477391);
        assert_eq!(
            prover.challenge_zerocopy_array::<u32, 2>("6")?,
            [341654301, 3531851372]
        );
        prover.hint_zerocopy("7", &7_u16)?;
        prover.hint_zerocopy_slice("8", &[8_u16, 9])?;
        prover.hint_zerocopy_dynamic("9", &[10_u16, 11])?;
        prover.end_protocol::<ProverState>("test all")?;
        let proof = prover.finalize()?;
        assert_eq!(
            hex::encode(&proof),
            "00004040000080400000a040070008000900040000000a000b00"
        );

        let mut verifier: VerifierState = VerifierState::new(pattern.into(), &proof);
        verifier.begin_protocol::<ProverState>("test all")?;
        verifier.public_zerocopy::<f32>("1", &1.0)?;
        verifier.public_zerocopy_slice::<f32>("2", &[2.0, 3.0])?;
        assert!(verifier
            .message_zerocopy::<f32>("3")?
            .total_cmp(&3.0)
            .is_eq());
        assert!(verifier
            .message_zerocopy_array::<f32, 2>("4")?
            .iter()
            .zip(&[4.0, 5.0])
            .all(|(l, r)| l.total_cmp(r).is_eq()));
        assert_eq!(verifier.challenge_zerocopy::<u32>("5")?, 1082477391);
        assert_eq!(
            verifier.challenge_zerocopy_array::<u32, 2>("6")?,
            [341654301, 3531851372]
        );
        assert_eq!(verifier.hint_zerocopy::<u16>("7")?, 7);
        assert_eq!(verifier.hint_zerocopy_array::<u16, 2>("8")?, [8, 9]);
        assert_eq!(
            verifier.hint_zerocopy_dynamic_vec::<u16>("9")?,
            vec![10, 11]
        );
        verifier.end_protocol::<ProverState>("test all")?;
        verifier.finalize()?;

        Ok(())
    }
}
