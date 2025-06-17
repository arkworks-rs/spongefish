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
        self.pattern.interact(Interaction::new::<[U]>(
            Hierarchy::Atomic,
            Kind::Message,
            "fill_next_units",
            Length::Fixed(input.len()),
        ));
        U::read(&mut self.narg_string, input)?;
        self.duplex_sponge.absorb_unchecked(input);
        Ok(())
    }

    /// Read a hint from the NARG string. Returns the number of units read.
    pub fn hint_bytes(&mut self) -> Result<&'a [u8], std::io::Error> {
        self.pattern.interact(Interaction::new::<[U]>(
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
}

impl<H: DuplexSpongeInterface<U>, U: Unit> UnitTranscript<U> for VerifierState<'_, H, U> {
    /// Add native elements to the sponge without writing them to the NARG string.
    #[inline]
    fn public_units(&mut self, input: &[U]) {
        self.pattern.interact(Interaction::new::<[U]>(
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
        self.pattern.interact(Interaction::new::<[U]>(
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
            .begin_message::<[u8]>("fill_next_bytes", Length::Fixed(input.len()));
        self.fill_next_units(input)?;
        self.pattern
            .end_message::<[u8]>("fill_next_bytes", Length::Fixed(input.len()));
        Ok(())
    }
}

// #[cfg(test)]
#[cfg(feature = "disabled")]
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

    #[test]
    fn test_hint_bytes_verifier_valid_hint() {
        // Domain separator commits to a hint
        let domsep: DomainSeparator<DummySponge> = DomainSeparator::new("valid").hint("hint");

        let mut prover = domsep.to_prover_state();

        let hint = b"abc123";
        prover.hint_bytes(hint).unwrap();

        let narg = prover.narg_string();

        let mut verifier = domsep.to_verifier_state(narg);
        let result = verifier.hint_bytes().unwrap();
        assert_eq!(result, hint);
    }

    #[test]
    fn test_hint_bytes_verifier_empty_hint() {
        // Commit to a hint instruction
        let domsep: DomainSeparator<DummySponge> = DomainSeparator::new("empty").hint("hint");

        let mut prover = domsep.to_prover_state();

        let hint = b"";
        prover.hint_bytes(hint).unwrap();

        let narg = prover.narg_string();

        let mut verifier = domsep.to_verifier_state(narg);
        let result = verifier.hint_bytes().unwrap();
        assert_eq!(result, b"");
    }

    #[test]
    fn test_hint_bytes_verifier_no_hint_op() {
        // No hint instruction in domain separator
        let domsep: DomainSeparator<DummySponge> = DomainSeparator::new("nohint");

        // Manually construct a hint buffer (length = 6, followed by bytes)
        let mut narg = vec![6, 0, 0, 0]; // length prefix for 6
        narg.extend_from_slice(b"abc123");

        let mut verifier = domsep.to_verifier_state(&narg);

        assert!(verifier.hint_bytes().is_err());
    }

    #[test]
    fn test_hint_bytes_verifier_length_prefix_too_short() {
        // Valid hint domain separator
        let domsep: DomainSeparator<DummySponge> = DomainSeparator::new("short").hint("hint");

        // Provide only 3 bytes, which is not enough for a u32 length
        let narg = &[1, 2, 3]; // less than 4 bytes

        let mut verifier = domsep.to_verifier_state(narg);

        let err = verifier.hint_bytes().unwrap_err();
        assert!(
            format!("{err}").contains("Insufficient transcript remaining for hint"),
            "Expected error for short prefix, got: {err}"
        );
    }

    #[test]
    fn test_hint_bytes_verifier_declared_hint_too_long() {
        // Valid hint domain separator
        let domsep: DomainSeparator<DummySponge> = DomainSeparator::new("loverflow").hint("hint");

        // Prefix says "5 bytes", but we only supply 2
        let narg = &[5, 0, 0, 0, b'a', b'b'];

        let mut verifier = domsep.to_verifier_state(narg);

        let err = verifier.hint_bytes().unwrap_err();
        assert!(
            format!("{err}").contains("Insufficient transcript remaining"),
            "Expected error for hint length > actual NARG bytes, got: {err}"
        );
    }
}
