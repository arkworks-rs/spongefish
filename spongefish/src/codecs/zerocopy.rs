//! [`zerocopy`] allows safe and efficient conversion to/from bytes for types that have
//! simple in-memory representations.

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use super::{
    bytes::{BytesCommon, BytesProver},
    BytesVerifier,
};
use crate::{
    transcript::{Label, Length},
    Unit, UnitCommon, UnitPattern, UnitProver, UnitVerifier,
};

pub trait ZeroCopyPattern<U, T>: UnitPattern<U>
where
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn public_zerocopy(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
    fn public_zerocopies(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>;
    fn message_zerocopy(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
    fn message_zerocopies(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>;
    fn challenge_zerocopy(&mut self, label: impl Into<Label>) -> Result<(), Self::Error>;
    fn challenge_zerocopies(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error>;

    fn hint_zerocopy(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Scalar)?;
        self.hint_bytes("zerocopy-bytes", size_of::<T>())?;
        self.end_hint::<T>(label.clone(), Length::Scalar)?;
        Ok(())
    }
    fn hint_zerocopies(&mut self, label: impl Into<Label>, size: usize) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Dynamic)?;
        self.hint_bytes("zerocopy-bytes-dynamic", size * size_of::<T>())?;
        self.end_hint::<T>(label.clone(), Length::Dynamic)
    }
    fn hint_zerocopies_dynamic(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_hint::<T>(label.clone(), Length::Dynamic)?;
        self.hint_bytes_dynamic("zerocopy-bytes-dynamic")?;
        self.end_hint::<T>(label.clone(), Length::Dynamic)
    }
}

pub trait ZeroCopyCommon<U, T>: UnitCommon<U>
where
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn public_zerocopy(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>;

    fn public_zerocopy_slice(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>;

    fn challenge_zerocopy_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>;

    fn challenge_zerocopy(&mut self, label: impl Into<Label>) -> Result<T, Self::Error> {
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
    ) -> Result<[T; N], Self::Error> {
        let mut result = <[T; N]>::new_zeroed();
        self.challenge_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    fn challenge_zerocopy_vec(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<T>, Self::Error> {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.challenge_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }
}

pub trait ZeroCopyProver<U, T>: UnitProver<U> + ZeroCopyCommon<U, T>
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
}

pub trait ZeroCopyVerifier<'a, U, T>: UnitVerifier<'a, U> + ZeroCopyCommon<U, T>
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

    fn message_zerocopy_array<const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[T; N], Self::Error> {
        let mut result = <[T; N]>::new_zeroed();
        self.message_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    fn message_zerocopy_vec(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<T>, Self::Error> {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.message_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }
}

/// Implementation of [`ZeroCopyHintProver`] for all [`UnitProver`].
pub trait ZeroCopyHintProver<U, T>: UnitProver<U>
where
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn hint_zerocopy(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error>;

    fn hint_zerocopy_dynamic(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error>;
}

/// Implementation of [`ZeroCopyHintVerifier`] for all [`UnitVerifier`].
pub trait ZeroCopyHintVerifier<'a, U, T>: UnitVerifier<'a, U>
where
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn hint_zerocopy_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error>;

    fn hint_zerocopy_slice_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>;

    fn hint_zerocopy_array<const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[T; N], Self::Error> {
        let mut result = <[T; N]>::new_zeroed();
        self.hint_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    fn hint_zerocopy_vec(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<T>, Self::Error> {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.hint_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    fn hint_zerocopy_dynamic_slice_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error>;

    fn hint_zerocopy_dynamic_vec(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<T>, Self::Error> {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.hint_zerocopy_dynamic_slice_out(label, &mut result)?;
        Ok(result)
    }
}

/// Implementation of [`ZeroCopyPattern`] for [`BytesPattern`].
impl<P, U, T> ZeroCopyPattern<U, T> for P
where
    P: BytesCommon<U>,
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn public_zerocopy(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_public::<T>(label.clone(), Length::Scalar)?;
        self.public_bytes("zerocopy-bytes", size_of::<T>())?;
        self.end_public::<T>(label, Length::Scalar)
    }

    fn public_zerocopies(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn message_zerocopy(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        todo!()
    }

    fn message_zerocopies(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn challenge_zerocopy(&mut self, label: impl Into<Label>) -> Result<(), Self::Error> {
        todo!()
    }

    fn challenge_zerocopies(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

/// Implementation of [`ZeroCopyCommon`] for [`BytesCommon`].
impl<P, U, T> ZeroCopyCommon<U, T> for P
where
    P: BytesCommon<U>,
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn public_zerocopy(&mut self, label: impl Into<Label>, value: &T) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_public::<T>(label.clone(), Length::Scalar)?;
        self.public_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_public::<T>(label, Length::Scalar)
    }

    fn public_zerocopy_slice(
        &mut self,
        label: impl Into<Label>,
        value: &[T],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_public::<T>(label.clone(), Length::Fixed(value.len()))?;
        self.public_bytes("zerocopy-bytes", value.as_bytes())?;
        self.end_public::<T>(label, Length::Fixed(value.len()))
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

/// Implementation of [`ZeroCopyProver`] for  [`BytesProver`]s.
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
}

/// Implementation of [`ZeroCopyVerifier`] for  [`BytesVerifier`]s.
impl<'a, P, U, T> ZeroCopyVerifier<'a, U, T> for P
where
    P: BytesVerifier<'a, U>,
    U: Unit,
    T: Immutable + FromBytes + IntoBytes,
{
    fn message_zerocopy_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut T,
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Scalar)?;
        self.message_bytes_out("zerocopy-bytes", out.as_mut_bytes())?;
        self.end_message::<T>(label, Length::Scalar)
    }

    fn message_zerocopy_slice_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [T],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<T>(label.clone(), Length::Fixed(out.len()))?;
        self.message_bytes_out("zerocopy-bytes", out.as_mut_bytes())?;
        self.end_message::<T>(label, Length::Fixed(out.len()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::transcript::TranscriptRecorder;

    #[test]
    fn test_all_ops() {
        /// Test all operations in UnitPattern.
        #[test]
        fn test_prover_state_unit_pattern() -> Result<(), Box<dyn Error>> {
            let mut pattern = TranscriptRecorder::<u8>::new();
            pattern.begin_protocol::<ProverState>("test all")?;
            let pattern = pattern.finalize()?;

            let mut prover: ProverState = pattern.into();
            prover.begin_protocol::<ProverState>("test all")?;
            prover.ratchet()?;
            prover.public_unit("1", &1)?;
            prover.public_units("2", 2_u32.as_bytes())?;
            prover.message_unit("3", &3)?;
            prover.message_units("4", 4_u32.as_bytes())?;
            assert_eq!(prover.challenge_unit("5")?, 128);
            assert_eq!(prover.challenge_units_array("6")?, [72, 136, 56, 161]);
            prover.hint_bytes("7", 7_u32.as_bytes())?;
            prover.hint_bytes_dynamic("8", &[8, 9, 10])?;
            prover.end_protocol::<ProverState>("test all")?;
            let proof = prover.finalize()?;

            assert_eq!(hex::encode(proof), "0304000000070000000300000008090a");

            Ok(())
        }
    }
}
