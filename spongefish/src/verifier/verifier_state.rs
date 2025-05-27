use std::{
    io::{Error as IOError, ErrorKind, Read},
    marker::PhantomData,
    slice::from_mut,
    sync::Arc,
};

use thiserror::Error;

use super::Verifier;
use crate::{
    duplex_sponge::{DuplexSpongeInterface, Unit},
    transcript::{
        Hierarchy, Interaction, InteractionError, Kind, Label, Length, Transcript,
        TranscriptPattern, TranscriptPlayer,
    },
    DefaultHash,
};

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("Interaction error: {}", .0)]
    Interaction(#[from] InteractionError),
    #[error("Error parsing narg_string: {}", .0)]
    IO(#[from] IOError),
}

/// [`VerifierState`] is the verifier state.
///
/// Internally, it simply contains a stateful hash.
/// Given as input an [`DomainSeparator`] and a NARG string, it allows to
/// de-serialize elements from the NARG string and make them available to the zero-knowledge verifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VerifierState<'a, H = DefaultHash, U = u8>
where
    H: DuplexSpongeInterface<U>,
    U: Unit,
{
    /// The transcript being followed.
    transcript: TranscriptPlayer,

    /// The public coins for the protocol
    duplex_sponge: H,

    /// The encoded data.
    narg_string: &'a [u8],

    /// Unit type of the sponge (defaults to `u8`)
    _unit: PhantomData<U>,
}

impl<'a, U: Unit, H: DuplexSpongeInterface<U>> VerifierState<'a, H, U> {
    /// Creates a new [`VerifierState`] instance with the given sponge and domain separator.
    ///
    /// The resulting object will act as the verifier in a zero-knowledge protocol.
    ///
    /// ```
    /// # use spongefish::*;
    ///
    /// let domsep = DomainSeparator::<DefaultHash>::new("📝").absorb(1, "inhale 🫁").squeeze(32, "exhale 🎏");
    /// // A silly NARG string for the example.
    /// let narg_string = &[0x42];
    /// let mut verifier_state = domsep.to_verifier_state(narg_string);
    /// assert_eq!(verifier_state.next_bytes().unwrap(), [0x42]);
    /// let challenge = verifier_state.challenge_bytes::<32>();
    /// assert!(challenge.is_ok());
    /// assert_ne!(challenge.unwrap(), [0; 32]);
    /// ```
    #[must_use]
    pub fn new(pattern: Arc<TranscriptPattern>, narg_string: &'a [u8]) -> Self {
        let domain_separator = pattern.domain_separator();
        Self {
            transcript: TranscriptPlayer::new(pattern),
            duplex_sponge: H::new(domain_separator),
            narg_string,
            _unit: PhantomData,
        }
    }

    pub fn finalize(mut self) -> Result<(), InteractionError> {
        // Zero sensitive state
        self.duplex_sponge.zeroize();

        // Finalize the transcript (will panic if called twice)
        self.transcript.finalize()?;
        Ok(())
    }
}

impl<'a, H, U> Transcript for VerifierState<'a, H, U>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    type Error = VerifierError;

    fn begin<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.transcript
            .interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length))?;
        Ok(())
    }

    fn end<T: ?Sized>(
        &mut self,
        label: impl Into<Label>,
        kind: Kind,
        length: Length,
    ) -> Result<(), Self::Error> {
        self.transcript
            .interact(Interaction::new::<T>(Hierarchy::End, kind, label, length))?;
        Ok(())
    }
}

impl<'a, H, U> Verifier<'a, U> for VerifierState<'a, H, U>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    fn ratchet(&mut self) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            "ratchet",
            Length::Scalar,
        ))?;
        self.duplex_sponge.ratchet();
        Ok(())
    }

    fn message_unit_out(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &mut U,
    ) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Scalar,
        ))?;
        let value = from_mut(value);
        U::read(&mut self.narg_string, value)?;
        self.duplex_sponge.absorb(value);
        Ok(())
    }

    fn message_units_out(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &mut [U],
    ) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(value.len()),
        ))?;
        U::read(&mut self.narg_string, value)?;
        self.duplex_sponge.absorb(value);
        Ok(())
    }

    fn challenge_unit_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut U,
    ) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Scalar,
        ))?;
        self.duplex_sponge.squeeze(from_mut(out));
        Ok(())
    }

    fn challenge_units_out(
        &mut self,
        label: impl Into<Label>,
        out: &mut [U],
    ) -> Result<(), Self::Error> {
        self.transcript.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(out.len()),
        ))?;
        self.duplex_sponge.squeeze(out);
        Ok(())
    }

    fn hint_bytes(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        size: usize,
    ) -> Result<&'a [u8], Self::Error> {
        self.transcript.interact(Interaction::new::<[u8]>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Fixed(size),
        ))?;
        if self.narg_string.len() < size {
            return Err(VerifierError::IO(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "insufficient bytes remaining in narg_string",
            )));
        }
        let bytes = &self.narg_string[..size];
        self.narg_string = &self.narg_string[size..];
        Ok(bytes)
    }

    fn hint_bytes_dynamic(
        &mut self,
        label: impl Into<crate::transcript::Label>,
    ) -> Result<&'a [u8], Self::Error> {
        self.transcript.interact(Interaction::new::<[u8]>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ))?;
        // Read length prefix
        if self.narg_string.len() < 4 {
            return Err(VerifierError::IO(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "insufficient bytes remaining in narg_string",
            )));
        }
        let size = u32::from_le_bytes(self.narg_string[..4].try_into().unwrap()) as usize;
        self.narg_string = &self.narg_string[4..];

        // Read bytes
        if self.narg_string.len() < size {
            return Err(VerifierError::IO(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "insufficient bytes remaining in narg_string",
            )));
        }
        let bytes = &self.narg_string[..size];
        self.narg_string = &self.narg_string[size..];
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    #[derive(Default, Clone)]
    pub struct DummySponge {
        pub absorbed: Rc<RefCell<Vec<u8>>>,
        pub squeezed: Rc<RefCell<Vec<u8>>>,
        pub ratcheted: Rc<RefCell<bool>>,
    }

    impl zeroize::Zeroize for DummySponge {
        fn zeroize(&mut self) {
            self.absorbed.borrow_mut().clear();
            self.squeezed.borrow_mut().clear();
            *self.ratcheted.borrow_mut() = false;
        }
    }

    impl DummySponge {
        fn new_inner() -> Self {
            Self {
                absorbed: Rc::new(RefCell::new(Vec::new())),
                squeezed: Rc::new(RefCell::new(Vec::new())),
                ratcheted: Rc::new(RefCell::new(false)),
            }
        }
    }

    impl DuplexSpongeInterface<u8> for DummySponge {
        fn new(_iv: [u8; 32]) -> Self {
            Self::new_inner()
        }

        fn absorb(&mut self, input: &[u8]) -> &mut Self {
            self.absorbed.borrow_mut().extend_from_slice(input);
            self
        }

        fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
            for (i, byte) in output.iter_mut().enumerate() {
                *byte = i as u8;
            }
            self.squeezed.borrow_mut().extend_from_slice(output);
            self
        }

        fn ratchet(&mut self) -> &mut Self {
            *self.ratcheted.borrow_mut() = true;
            self
        }
    }

    #[test]
    fn test_new_verifier_state_constructs_correctly() {
        let ds = DomainSeparator::<DummySponge>::new("test");
        let transcript = b"abc";
        let vs = VerifierState::<DummySponge>::new(&ds, transcript);
        assert_eq!(vs.narg_string, b"abc");
    }

    #[test]
    fn test_fill_next_units_reads_and_absorbs() {
        let ds = DomainSeparator::<DummySponge>::new("x").absorb(3, "input");
        let mut vs = VerifierState::<DummySponge>::new(&ds, b"abc");
        let mut buf = [0u8; 3];
        let res = vs.fill_next_units(&mut buf);
        assert!(res.is_ok());
        assert_eq!(buf, *b"abc");
        assert_eq!(*vs.hash_state.ds().absorbed.borrow(), b"abc");
    }

    #[test]
    fn test_fill_next_units_with_insufficient_data_errors() {
        let ds = DomainSeparator::<DummySponge>::new("x").absorb(4, "fail");
        let mut vs = VerifierState::<DummySponge>::new(&ds, b"xy");
        let mut buf = [0u8; 4];
        let res = vs.fill_next_units(&mut buf);
        assert!(res.is_err());
    }

    #[test]
    fn test_ratcheting_success() {
        let ds = DomainSeparator::<DummySponge>::new("x").ratchet();
        let mut vs = VerifierState::<DummySponge>::new(&ds, &[]);
        assert!(vs.ratchet().is_ok());
        assert!(*vs.hash_state.ds().ratcheted.borrow());
    }

    #[test]
    fn test_ratcheting_wrong_op_errors() {
        let ds = DomainSeparator::<DummySponge>::new("x").absorb(1, "wrong");
        let mut vs = VerifierState::<DummySponge>::new(&ds, b"z");
        assert!(vs.ratchet().is_err());
    }

    #[test]
    fn test_unit_transcript_public_units() {
        let ds = DomainSeparator::<DummySponge>::new("x").absorb(2, "public");
        let mut vs = VerifierState::<DummySponge>::new(&ds, b"..");
        assert!(vs.public_units(&[1, 2]).is_ok());
        assert_eq!(*vs.hash_state.ds().absorbed.borrow(), &[1, 2]);
    }

    #[test]
    fn test_unit_transcript_fill_challenge_units() {
        let ds = DomainSeparator::<DummySponge>::new("x").squeeze(4, "c");
        let mut vs = VerifierState::<DummySponge>::new(&ds, b"abcd");
        let mut out = [0u8; 4];
        assert!(vs.fill_challenge_units(&mut out).is_ok());
        assert_eq!(out, [0, 1, 2, 3]);
    }

    #[test]
    fn test_fill_next_bytes_impl() {
        let ds = DomainSeparator::<DummySponge>::new("x").absorb(3, "byte");
        let mut vs = VerifierState::<DummySponge>::new(&ds, b"xyz");
        let mut out = [0u8; 3];
        assert!(vs.fill_next_bytes(&mut out).is_ok());
        assert_eq!(out, *b"xyz");
    }
}
