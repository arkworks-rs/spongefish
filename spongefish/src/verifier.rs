use std::{marker::PhantomData, sync::Arc};

use crate::{
    duplex_sponge::{DuplexSpongeInterface, Unit},
    pattern::{Hierarchy, Interaction, InteractionPattern, Kind, Length, Pattern, PatternPlayer},
    traits::{BytesToUnitDeserialize, UnitTranscript},
    DefaultHash,
};

/// [`VerifierState`] is the verifier state.
///
/// Internally, it simply contains a stateful hash.
/// Given as input an [`DomainSeparator`] and a NARG string, it allows to
/// de-serialize elements from the NARG string and make them available to the zero-knowledge verifier.
pub struct VerifierState<'a, H = DefaultHash, U = u8>
where
    H: DuplexSpongeInterface<U>,
    U: Unit,
{
    pub(crate) pattern: PatternPlayer,
    pub(crate) duplex_sponge: H,
    pub(crate) narg_string: &'a [u8],
    pub(crate) _unit_type: PhantomData<U>,
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
    pub fn new(pattern: Arc<InteractionPattern>, narg_string: &'a [u8]) -> Self {
        let iv = pattern.domain_separator();
        Self {
            pattern: PatternPlayer::new(pattern),
            duplex_sponge: H::new(iv),
            narg_string,
            _unit_type: PhantomData,
        }
    }

    /// Read `input.len()` elements from the NARG string.
    #[inline]
    pub fn fill_next_units(&mut self, input: &mut [U]) -> Result<(), std::io::Error> {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            "units",
            Length::Fixed(input.len()),
        ));
        U::read(&mut self.narg_string, input)?;
        self.duplex_sponge.absorb_unchecked(input);
        Ok(())
    }

    /// Read a hint from the NARG string. Returns the number of units read.
    pub fn hint_bytes(&mut self) -> Result<&'a [u8], std::io::Error> {
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            "hint_bytes",
            Length::Dynamic,
        ));

        // Ensure at least 4 bytes are available for the length prefix
        if self.narg_string.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Insufficient transcript remaining for hint",
            ));
        }

        // Read 4-byte little-endian length prefix
        let len = u32::from_le_bytes(self.narg_string[..4].try_into().unwrap()) as usize;
        let rest = &self.narg_string[4..];

        // Ensure the rest of the slice has `len` bytes
        if rest.len() < len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "Insufficient transcript remaining, got {}, need {len}",
                    rest.len()
                ),
            ));
        }

        // Split the hint and advance the transcript
        let (hint, remaining) = rest.split_at(len);
        self.narg_string = remaining;

        Ok(hint)
    }

    /// Signals the end of the statement.
    #[inline]
    pub fn ratchet(&mut self) {
        self.pattern.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            "ratchet",
            Length::None,
        ));
        self.duplex_sponge.ratchet_unchecked();
    }

    /// Abort the verifier session without completing playback.
    ///
    /// Any remaining expected interactions are discarded.
    pub fn abort(mut self) {
        self.pattern.abort();
    }

    /// Finalize the verifier session, asserting all interactions were consumed.
    pub fn finalize(self) {
        self.pattern.finalize();
    }
}

impl<H: DuplexSpongeInterface<U>, U: Unit> UnitTranscript<U> for VerifierState<'_, H, U> {
    /// Add native elements to the sponge without writing them to the NARG string.
    #[inline]
    fn public_units(&mut self, input: &[U]) {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            "public_units",
            Length::Fixed(input.len()),
        ));
        self.duplex_sponge.absorb_unchecked(input);
    }

    /// Fill `input` with units sampled uniformly at random.
    #[inline]
    fn fill_challenge_units(&mut self, input: &mut [U]) {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "fill_challenge_units",
            Length::Fixed(input.len()),
        ));
        self.duplex_sponge.squeeze_unchecked(input);
    }
}

impl<H: DuplexSpongeInterface<U>, U: Unit> core::fmt::Debug for VerifierState<'_, H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("VerifierState").field(&self.pattern).finish()
    }
}

impl<H: DuplexSpongeInterface<u8>> BytesToUnitDeserialize for VerifierState<'_, H, u8> {
    /// Read the next `input.len()` bytes from the NARG string and return them.
    #[inline]
    fn fill_next_bytes(&mut self, input: &mut [u8]) -> Result<(), std::io::Error> {
        self.pattern
            .begin_message::<u8>("bytes", Length::Fixed(input.len()));
        self.fill_next_units(input)?;
        self.pattern
            .end_message::<u8>("bytes", Length::Fixed(input.len()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, sync::Arc};

    use super::*;
    use crate::{
        codecs::{bytes::Pattern as _, unit::Pattern},
        pattern::PatternState,
        ProverState,
    };

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

        fn absorb_unchecked(&mut self, input: &[u8]) -> &mut Self {
            self.absorbed.borrow_mut().extend_from_slice(input);
            self
        }

        fn squeeze_unchecked(&mut self, output: &mut [u8]) -> &mut Self {
            for (i, byte) in output.iter_mut().enumerate() {
                *byte = i as u8;
            }
            self.squeezed.borrow_mut().extend_from_slice(output);
            self
        }

        fn ratchet_unchecked(&mut self) -> &mut Self {
            *self.ratcheted.borrow_mut() = true;
            self
        }
    }

    #[test]
    fn test_new_verifier_state_constructs_correctly() {
        let pattern = PatternState::<u8>::new().finalize();
        let transcript = b"abc";
        let vs = VerifierState::<DummySponge>::new(Arc::new(pattern), transcript);
        assert_eq!(vs.narg_string, b"abc");
        vs.finalize();
    }

    #[test]
    fn test_fill_next_units_reads_and_absorbs() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_units("units", 3);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), b"abc");
        let mut buf = [0u8; 3];
        assert!(vs.fill_next_units(&mut buf).is_ok());
        assert_eq!(buf, *b"abc");
        assert_eq!(*vs.duplex_sponge.absorbed.borrow(), b"abc");
        vs.finalize();
    }

    #[test]
    fn test_fill_next_units_with_insufficient_data_errors() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_units("units", 4);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), b"xy");
        let mut buf = [0u8; 4];
        assert!(vs.fill_next_units(&mut buf).is_err());
        vs.abort();
    }

    #[test]
    fn test_ratcheting_success() {
        let mut pattern = PatternState::<u8>::new();
        pattern.ratchet();
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), &[]);
        vs.ratchet();
        assert!(*vs.duplex_sponge.ratcheted.borrow());
        vs.finalize();
    }

    #[test]
    #[should_panic(
        expected = "Received interaction Atomic Protocol ratchet None (), but expected Atomic Message units Fixed(1) u8"
    )]
    fn test_ratcheting_wrong_op_errors() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_units("units", 1);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), &[]);
        vs.ratchet();
    }

    #[test]
    fn test_unit_transcript_public_units() {
        let mut pattern = PatternState::<u8>::new();
        pattern.public_units("public_units", 2);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), b"..");
        vs.public_units(&[1, 2]);
        assert_eq!(*vs.duplex_sponge.absorbed.borrow(), &[1, 2]);
        vs.finalize();
    }

    #[test]
    fn test_unit_transcript_fill_challenge_units() {
        let mut pattern = PatternState::<u8>::new();
        pattern.challenge_units("fill_challenge_units", 4);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), b"abcd");
        let mut out = [0u8; 4];
        vs.fill_challenge_units(&mut out);
        assert_eq!(out, [0, 1, 2, 3]);
        vs.finalize();
    }

    #[test]
    fn test_fill_next_bytes_impl() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_bytes("bytes", 3);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), b"xyz");
        let mut out = [0u8; 3];
        assert!(vs.fill_next_bytes(&mut out).is_ok());
        assert_eq!(out, *b"xyz");
        vs.finalize();
    }

    #[test]
    fn test_hint_bytes_verifier_valid_hint() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic("hint_bytes");
        let pattern = pattern.finalize();

        let hint = b"abc123";
        let mut prover: ProverState = ProverState::from(&pattern);
        prover.hint_bytes(hint);
        let narg = prover.finalize();
        assert_eq!(hex::encode(&narg), "06000000616263313233");

        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern.clone()), &narg);
        let result = vs.hint_bytes().unwrap();
        assert_eq!(result, hint);
        vs.finalize();
    }

    #[test]
    fn test_hint_bytes_verifier_empty_hint() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic("hint_bytes");
        let pattern = pattern.finalize();

        let hint = b"";
        let mut prover: ProverState = ProverState::from(&pattern);
        prover.hint_bytes(hint);
        let narg = prover.finalize();

        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern.clone()), &narg);
        let result = vs.hint_bytes().unwrap();
        assert_eq!(result, b"");
        vs.finalize();
    }

    #[test]
    #[should_panic(
        expected = "Received interaction, but no more expected interactions: Atomic Hint hint_bytes Dynamic u8"
    )]
    fn test_hint_bytes_verifier_no_hint_op() {
        let pattern = PatternState::<u8>::new().finalize();

        // Manually construct a hint buffer (length = 6, followed by bytes)
        let narg = hex::decode("06000000616263313233").unwrap();

        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern), &narg);
        vs.hint_bytes().unwrap();
    }

    #[test]
    fn test_hint_bytes_verifier_length_prefix_too_short() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic("hint_bytes");
        let pattern = pattern.finalize();

        // Provide only 3 bytes, which is not enough for a u32 length
        let narg = &[1, 2, 3]; // less than 4 bytes

        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern), narg);
        let err = vs.hint_bytes().unwrap_err();
        assert!(format!("{err}").contains("Insufficient transcript remaining for hint"));
        vs.abort();
    }

    #[test]
    fn test_hint_bytes_verifier_declared_hint_too_long() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic("hint_bytes");
        let pattern = pattern.finalize();

        let narg = [5u8, 0, 0, 0, b'a', b'b'];
        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern), &narg);
        let err = vs.hint_bytes().unwrap_err();
        assert!(format!("{err}").contains("Insufficient transcript remaining"));
        vs.abort();
    }
}
