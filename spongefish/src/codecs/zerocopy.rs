//! [`zerocopy`] allows safe and efficient conversion to/from bytes for types that have
//! simple in-memory representations.
//!
//!
//! ## Design note
//!
//! It would logically make more sense to put the generic and trait bounds on the
//! trait itself, as
//!
//! ```ignore
//! pub trait HintPattern<T: Item> {
//!     fn hint_zerocopy(&mut self, label: Label);
//!     fn hint_zerocopy_many(&mut self, label: Label, size: usize);
//!     fn hint_zerocopy_dynamic(&mut self, label: Label);
//! }
//! ```
//!
//! The downside is that for many functions the type `T` is ambiguous at the call site, and to
//! disambiguate it, we would have to use the fully qualified syntax:
//!
//! ```ignore
//! <PatternState as HintPattern<u16>>::hint_zerocopy(&mut pattern, "label");
//! ```
//!
//! This is not very ergonomic, so instead we put the generic and trait bounds on the functions
//! themselves, which allows us to use the more ergonomic syntax:
//!
//! ```ignore
//! pattern.hint_zerocopy::<u16>("label");
//! ```
//!
//! This is a bit more verbose in implementation, but more convenient to use.

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    codecs::{bytes, unit},
    transcript::{self, Label, Length},
    verifier_state::VerifierError,
};

pub trait Item: Immutable + KnownLayout + FromBytes + IntoBytes {}

pub trait HintPattern {
    fn hint_zerocopy<T: Item>(&mut self, label: Label);
    fn hint_zerocopy_many<T: Item>(&mut self, label: Label, size: usize);
    fn hint_zerocopy_dynamic<T: Item>(&mut self, label: Label);
}

pub trait HintProver {
    fn hint_zerocopy<T: Item>(&mut self, label: Label, value: &T);
    fn hint_zerocopy_slice<T: Item>(&mut self, label: Label, value: &[T]);
    fn hint_zerocopy_dynamic<T: Item>(&mut self, label: Label, value: &[T]);
}

pub trait HintVerifier<'a> {
    fn hint_zerocopy_out<T: Item>(
        &mut self,
        label: Label,
        out: &mut T,
    ) -> Result<(), VerifierError>;

    fn hint_zerocopy<T: Item>(&mut self, label: Label) -> Result<T, VerifierError> {
        let mut result = T::new_zeroed();
        self.hint_zerocopy_out(label, &mut result)?;
        Ok(result)
    }

    /// Return a direct reference to the transcript bytes if [`T`] is an [`Unaligned`] type.
    fn hint_zerocopy_ref<T: Item + Unaligned>(
        &mut self,
        label: Label,
    ) -> Result<&'a T, VerifierError>;

    fn hint_zerocopy_slice_out<T: Item>(
        &mut self,
        label: Label,
        out: &mut [T],
    ) -> Result<(), VerifierError>;

    fn hint_zerocopy_array<T: Item, const N: usize>(
        &mut self,
        label: Label,
    ) -> Result<[T; N], VerifierError> {
        let mut result = <[T; N]>::new_zeroed();
        self.hint_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    fn hint_zerocopy_vec<T: Item>(
        &mut self,
        label: Label,
        size: usize,
    ) -> Result<Vec<T>, VerifierError> {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.hint_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    /// Return a direct reference to the transcript bytes if [`T`] is an [`Unaligned`] type.
    fn hint_zerocopy_slice_ref<T: Item>(
        &mut self,
        label: Label,
        size: usize,
    ) -> Result<&'a [T], VerifierError>;

    fn hint_zerocopy_dynamic_vec<T: Item>(&mut self, label: Label)
        -> Result<Vec<T>, VerifierError>;

    /// Return a direct reference to the transcript bytes if [`T`] is an [`Unaligned`] type.
    fn hint_zerocopy_dynamic_slice_ref<T: Item + Unaligned>(
        &mut self,
        label: Label,
    ) -> Result<&'a [T], VerifierError>;
}

pub trait Pattern: HintPattern {
    fn public_zerocopy<T: Item>(&mut self, label: Label);
    fn public_zerocopy_many<T: Item>(&mut self, label: Label, size: usize);
    fn message_zerocopy<T: Item>(&mut self, label: Label);
    fn message_zerocopy_many<T: Item>(&mut self, label: Label, size: usize);
    fn challenge_zerocopy<T: Item>(&mut self, label: Label);
    fn challenge_zerocopy_many<T: Item>(&mut self, label: Label, size: usize);
}

pub trait Common {
    fn public_zerocopy<T: Item>(&mut self, label: Label, value: &T);
    fn public_zerocopy_slice<T: Item>(&mut self, label: Label, value: &[T]);
    fn challenge_zerocopy_out<T: Item>(&mut self, label: Label, out: &mut T);
    fn challenge_zerocopy<T: Item>(&mut self, label: Label) -> T {
        let mut result = T::new_zeroed();
        self.challenge_zerocopy_out(label, &mut result);
        result
    }
    fn challenge_zerocopy_slice_out<T: Item>(&mut self, label: Label, out: &mut [T]);
    fn challenge_zerocopy_array<T: Item, const N: usize>(&mut self, label: Label) -> [T; N] {
        let mut result = <[T; N]>::new_zeroed();
        self.challenge_zerocopy_slice_out(label, &mut result);
        result
    }
    fn challenge_zerocopy_vec<T: Item>(&mut self, label: Label, size: usize) -> Vec<T> {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.challenge_zerocopy_slice_out(label, &mut result);
        result
    }
}

pub trait Prover: Common + HintProver {
    fn message_zerocopy<T: Item>(&mut self, label: Label, value: &T);
    fn message_zerocopy_slice<T: Item>(&mut self, label: Label, value: &[T]);
}

pub trait Verifier<'a>: Common + HintVerifier<'a> {
    fn message_zerocopy_out<T: Item>(
        &mut self,
        label: Label,
        out: &mut T,
    ) -> Result<(), VerifierError>;

    fn message_zerocopy<T: Item>(&mut self, label: Label) -> Result<T, VerifierError> {
        let mut result = T::new_zeroed();
        self.message_zerocopy_out(label, &mut result)?;
        Ok(result)
    }

    fn message_zerocopy_slice_out<T: Item>(
        &mut self,
        label: Label,
        out: &mut [T],
    ) -> Result<(), VerifierError>;

    fn message_zerocopy_array<T: Item, const N: usize>(
        &mut self,
        label: Label,
    ) -> Result<[T; N], VerifierError> {
        let mut result = <[T; N]>::new_zeroed();
        self.message_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }

    fn message_zerocopy_vec<T: Item>(
        &mut self,
        label: Label,
        size: usize,
    ) -> Result<Vec<T>, VerifierError> {
        let mut result = T::new_vec_zeroed(size).expect("allocation failure");
        self.message_zerocopy_slice_out(label, &mut result)?;
        Ok(result)
    }
}

impl<T> Item for T where T: Immutable + KnownLayout + FromBytes + IntoBytes {}

/// Implementation of [`ZeroCopyHintPattern`] for all [`UnitPattern`].
impl<P> HintPattern for P
where
    P: transcript::Pattern + unit::Pattern,
{
    fn hint_zerocopy<T: Item>(&mut self, label: Label) {
        self.begin_hint::<T>(label, Length::Scalar);
        self.hint_bytes("zerocopy-bytes", size_of::<T>());
        self.end_hint::<T>(label, Length::Scalar);
    }

    fn hint_zerocopy_many<T: Item>(&mut self, label: Label, size: usize) {
        self.begin_hint::<[T]>(label, Length::Fixed(size));
        self.hint_bytes("zerocopy-bytes", size * size_of::<T>());
        self.end_hint::<[T]>(label, Length::Fixed(size));
    }

    fn hint_zerocopy_dynamic<T: Item>(&mut self, label: Label) {
        self.begin_hint::<[T]>(label, Length::Dynamic);
        self.hint_bytes_dynamic("zerocopy-bytes-dynamic");
        self.end_hint::<[T]>(label, Length::Dynamic);
    }
}

impl<P> HintProver for P
where
    P: transcript::Prover + unit::Prover,
{
    fn hint_zerocopy<T: Item>(&mut self, label: Label, value: &T) {
        self.begin_hint::<T>(label, Length::Scalar);
        self.hint_bytes("zerocopy-bytes", value.as_bytes());
        self.end_hint::<T>(label, Length::Scalar);
    }

    fn hint_zerocopy_slice<T: Item>(&mut self, label: Label, value: &[T]) {
        self.begin_hint::<[T]>(label, Length::Fixed(value.len()));
        self.hint_bytes("zerocopy-bytes", value.as_bytes());
        self.end_hint::<[T]>(label, Length::Fixed(value.len()));
    }

    fn hint_zerocopy_dynamic<T: Item>(&mut self, label: Label, value: &[T]) {
        self.begin_hint::<[T]>(label, Length::Dynamic);
        self.hint_bytes_dynamic("zerocopy-bytes-dynamic", value.as_bytes());
        self.end_hint::<[T]>(label, Length::Dynamic);
    }
}

impl<'a, P> HintVerifier<'a> for P
where
    P: transcript::Verifier + unit::Verifier<'a>,
{
    fn hint_zerocopy_out<T: Item>(
        &mut self,
        label: Label,
        out: &mut T,
    ) -> Result<(), VerifierError> {
        self.begin_hint::<T>(label, Length::Scalar);
        let bytes = out.as_mut_bytes();
        let slice = self.hint_bytes("zerocopy-bytes", bytes.len())?;
        bytes.copy_from_slice(slice);
        self.end_hint::<T>(label, Length::Scalar);
        Ok(())
    }

    fn hint_zerocopy_ref<T: Item>(&mut self, label: Label) -> Result<&'a T, VerifierError> {
        self.begin_hint::<T>(label, Length::Scalar);
        let slice = self.hint_bytes("zerocopy-bytes", size_of::<T>())?;
        let result = T::ref_from_bytes(slice).expect("TODO"); // TODO
        self.end_hint::<T>(label, Length::Scalar);
        Ok(result)
    }

    fn hint_zerocopy_slice_out<T: Item>(
        &mut self,
        label: Label,
        out: &mut [T],
    ) -> Result<(), VerifierError> {
        self.begin_hint::<[T]>(label, Length::Fixed(out.len()));
        let bytes = out.as_mut_bytes();
        let slice = self.hint_bytes("zerocopy-bytes", bytes.len())?;
        bytes.copy_from_slice(slice);
        self.end_hint::<[T]>(label, Length::Fixed(out.len()));
        Ok(())
    }

    fn hint_zerocopy_slice_ref<T: Item>(
        &mut self,
        label: Label,
        size: usize,
    ) -> Result<&'a [T], VerifierError> {
        self.begin_hint::<[T]>(label, Length::Fixed(size));
        let slice = self.hint_bytes("zerocopy-bytes", size * size_of::<T>())?;
        let result = <[T]>::ref_from_bytes(slice).expect("TODO"); // TODO
        self.end_hint::<[T]>(label, Length::Fixed(size));
        Ok(result)
    }

    fn hint_zerocopy_dynamic_vec<T: Item>(
        &mut self,
        label: Label,
    ) -> Result<Vec<T>, VerifierError> {
        self.begin_hint::<[T]>(label, Length::Dynamic);
        let slice = self.hint_bytes_dynamic("zerocopy-bytes-dynamic")?;
        if slice.len() % size_of::<T>() != 0 {
            todo!()
        }
        let mut result =
            T::new_vec_zeroed(slice.len() / size_of::<T>()).expect("allocation failure");
        result.as_mut_bytes().copy_from_slice(slice);
        self.end_hint::<[T]>(label, Length::Dynamic);
        Ok(result)
    }

    fn hint_zerocopy_dynamic_slice_ref<T: Item>(
        &mut self,
        label: Label,
    ) -> Result<&'a [T], VerifierError> {
        self.begin_hint::<[T]>(label, Length::Dynamic);
        let slice = self.hint_bytes_dynamic("zerocopy-bytes-dynamic")?;
        let result = <[T]>::ref_from_bytes(slice).expect("TODO"); // TODO
        self.end_hint::<[T]>(label, Length::Dynamic);
        Ok(result)
    }
}

/// Implementation of [`ZeroCopyPattern`] for [`BytesPattern`].
impl<P> Pattern for P
where
    P: HintPattern + transcript::Pattern + bytes::Pattern,
{
    fn public_zerocopy<T: Item>(&mut self, label: Label) {
        self.begin_public::<T>(label, Length::Scalar);
        self.public_bytes("zerocopy-bytes", size_of::<T>());
        self.end_public::<T>(label, Length::Scalar);
    }

    fn public_zerocopy_many<T: Item>(&mut self, label: Label, size: usize) {
        self.begin_public::<[T]>(label, Length::Fixed(size));
        self.public_bytes("zerocopy-bytes", size * size_of::<T>());
        self.end_public::<[T]>(label, Length::Fixed(size));
    }

    fn message_zerocopy<T: Item>(&mut self, label: Label) {
        self.begin_message::<T>(label, Length::Scalar);
        self.message_bytes("zerocopy-bytes", size_of::<T>());
        self.end_message::<T>(label, Length::Scalar);
    }

    fn message_zerocopy_many<T: Item>(&mut self, label: Label, size: usize) {
        self.begin_message::<[T]>(label, Length::Fixed(size));
        self.message_bytes("zerocopy-bytes", size * size_of::<T>());
        self.end_message::<[T]>(label, Length::Fixed(size));
    }

    fn challenge_zerocopy<T: Item>(&mut self, label: Label) {
        self.begin_challenge::<T>(label, Length::Scalar);
        self.challenge_bytes("zerocopy-bytes", size_of::<T>());
        self.end_challenge::<T>(label, Length::Scalar);
    }

    fn challenge_zerocopy_many<T: Item>(&mut self, label: Label, size: usize) {
        self.begin_challenge::<[T]>(label, Length::Fixed(size));
        self.challenge_bytes("zerocopy-bytes", size * size_of::<T>());
        self.end_challenge::<[T]>(label, Length::Fixed(size));
    }
}

/// Implementation of [`ZeroCopyCommon`] for [`BytesCommon`].
impl<P> Common for P
where
    P: transcript::Common + bytes::Common,
{
    fn public_zerocopy<T: Item>(&mut self, label: Label, value: &T) {
        self.begin_public::<T>(label, Length::Scalar);
        self.public_bytes("zerocopy-bytes", value.as_bytes());
        self.end_public::<T>(label, Length::Scalar);
    }

    fn public_zerocopy_slice<T: Item>(&mut self, label: Label, value: &[T]) {
        self.begin_public::<[T]>(label, Length::Fixed(value.len()));
        self.public_bytes("zerocopy-bytes", value.as_bytes());
        self.end_public::<[T]>(label, Length::Fixed(value.len()));
    }

    fn challenge_zerocopy_out<T: Item>(&mut self, label: Label, out: &mut T) {
        self.begin_challenge::<T>(label, Length::Scalar);
        self.challenge_bytes_out("zerocopy-bytes", out.as_mut_bytes());
        self.end_challenge::<T>(label, Length::Scalar);
    }

    fn challenge_zerocopy_slice_out<T: Item>(&mut self, label: Label, out: &mut [T]) {
        self.begin_challenge::<[T]>(label, Length::Fixed(out.len()));
        self.challenge_bytes_out("zerocopy-bytes", out.as_mut_bytes());
        self.end_challenge::<[T]>(label, Length::Fixed(out.len()));
    }
}

/// Implementation of [`ZeroCopyProver`] for  [`BytesProver`]s.
impl<P> Prover for P
where
    P: Common + HintProver + transcript::Prover + bytes::Prover,
{
    fn message_zerocopy<T: Item>(&mut self, label: Label, value: &T) {
        self.begin_message::<T>(label, Length::Scalar);
        self.message_bytes("zerocopy-bytes", value.as_bytes());
        self.end_message::<T>(label, Length::Scalar);
    }

    fn message_zerocopy_slice<T: Item>(&mut self, label: Label, value: &[T]) {
        self.begin_message::<[T]>(label, Length::Fixed(value.len()));
        self.message_bytes("zerocopy-bytes", value.as_bytes());
        self.end_message::<[T]>(label, Length::Fixed(value.len()));
    }
}

/// Implementation of [`ZeroCopyVerifier`] for  [`BytesVerifier`]s.
impl<'a, P> Verifier<'a> for P
where
    P: Common + HintVerifier<'a> + transcript::Verifier + bytes::Verifier,
{
    fn message_zerocopy_out<T: Item>(
        &mut self,
        label: Label,
        out: &mut T,
    ) -> Result<(), VerifierError> {
        self.begin_message::<T>(label, Length::Scalar);
        self.message_bytes_out("zerocopy-bytes", out.as_mut_bytes())?;
        self.end_message::<T>(label, Length::Scalar);
        Ok(())
    }

    fn message_zerocopy_slice_out<T: Item>(
        &mut self,
        label: Label,
        out: &mut [T],
    ) -> Result<(), VerifierError> {
        self.begin_message::<[T]>(label, Length::Fixed(out.len()));
        self.message_bytes_out("zerocopy-bytes", out.as_mut_bytes())?;
        self.end_message::<[T]>(label, Length::Fixed(out.len()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        transcript::{Pattern as _, PatternState},
        ProverState, VerifierState,
    };

    #[test]
    fn test_all_ops() -> anyhow::Result<()> {
        let mut pattern = PatternState::<u8>::new();
        pattern.begin_protocol::<ProverState>("test all");
        pattern.public_zerocopy::<f32>("1");
        pattern.public_zerocopy_many::<f32>("2", 2);
        pattern.message_zerocopy::<f32>("3");
        pattern.message_zerocopy_many::<f32>("4", 2);
        pattern.challenge_zerocopy::<u32>("5");
        pattern.challenge_zerocopy_many::<u32>("6", 2);
        pattern.hint_zerocopy::<u16>("7");
        pattern.hint_zerocopy_many::<u16>("8", 2);
        pattern.hint_zerocopy_dynamic::<u16>("9");
        pattern.end_protocol::<ProverState>("test all");
        let pattern = pattern.finalize();
        eprintln!("{pattern}");

        let mut prover: ProverState = ProverState::from(&pattern);
        prover.begin_protocol::<ProverState>("test all");
        prover.public_zerocopy::<f32>("1", &1.0);
        prover.public_zerocopy_slice::<f32>("2", &[2.0, 3.0]);
        prover.message_zerocopy("3", &3.0_f32);
        prover.message_zerocopy_slice("4", &[4.0_f32, 5.0]);
        assert_eq!(prover.challenge_zerocopy::<u32>("5"), 1621126262);
        assert_eq!(
            prover.challenge_zerocopy_array::<u32, 2>("6"),
            [1464286757, 1603471595]
        );
        prover.hint_zerocopy("7", &7_u16);
        prover.hint_zerocopy_slice("8", &[8_u16, 9]);
        prover.hint_zerocopy_dynamic("9", &[10_u16, 11]);
        prover.end_protocol::<ProverState>("test all");
        let proof = prover.finalize();
        assert_eq!(
            hex::encode(&proof),
            "00004040000080400000a040070008000900040000000a000b00"
        );

        let mut verifier: VerifierState = VerifierState::new(pattern.into(), &proof);
        verifier.begin_protocol::<ProverState>("test all");
        verifier.public_zerocopy::<f32>("1", &1.0);
        verifier.public_zerocopy_slice::<f32>("2", &[2.0, 3.0]);
        assert!(verifier
            .message_zerocopy::<f32>("3")?
            .total_cmp(&3.0)
            .is_eq());
        assert!(verifier
            .message_zerocopy_array::<f32, 2>("4")?
            .iter()
            .zip(&[4.0_f32, 5.0])
            .all(|(l, r)| l.total_cmp(r).is_eq()));
        assert_eq!(verifier.challenge_zerocopy::<u32>("5"), 1621126262);
        assert_eq!(
            verifier.challenge_zerocopy_array::<u32, 2>("6"),
            [1464286757, 1603471595]
        );
        assert_eq!(verifier.hint_zerocopy::<u16>("7")?, 7);
        assert_eq!(verifier.hint_zerocopy_array::<u16, 2>("8")?, [8, 9]);
        assert_eq!(
            verifier.hint_zerocopy_dynamic_vec::<u16>("9")?,
            vec![10, 11]
        );
        verifier.end_protocol::<ProverState>("test all");
        verifier.finalize();

        Ok(())
    }
}
