// XXX. before, absorb and squeeze were accepting arguments of type
// use ::core::num::NonZeroUsize;
// which was a pain to use
// (plain integers don't cast to NonZeroUsize automatically)

use std::{collections::VecDeque, marker::PhantomData};

use super::{
    duplex_sponge::{DuplexSpongeInterface, Unit},
    errors::DomainSeparatorMismatch,
};
use crate::ByteDomainSeparator;

/// This is the separator between operations in the domain separator
/// and as such is the only forbidden character in labels.
const SEP_BYTE: &str = "\0";

/// The domain separator of an interactive protocol.
///
/// An domain separator is a string that specifies the protocol in a simple,
/// non-ambiguous, human-readable format. A typical example is the following:
///
/// ```text
///     domain-separator A32generator A32public-key R A32commitment S32challenge A32response
/// ```
/// The domain-separator is a user-specified string uniquely identifying the end-user application  (to avoid cross-protocol attacks).
/// The letter `A` indicates the absorption of a public input (an `ABSORB`), while the letter `S` indicates the squeezing (a `SQUEEZE`) of a challenge.
/// The letter `R` indicates a ratcheting operation: ratcheting means invoking the hash function even on an incomplete block.
/// It provides forward secrecy and allows it to start from a clean rate.
/// After the operation type, is the number of elements in base 10 that are being absorbed/squeezed.
/// Then, follows the label associated with the element being absorbed/squeezed. This often comes from the underlying description of the protocol. The label cannot start with a digit or contain the NULL byte.
///
/// ## Guarantees
///
/// The struct [`DomainSeparator`] guarantees the creation of a valid domain separator string, whose lengths are coherent with the types described in the protocol. No information about the types themselves is stored in an domain separator.
/// This means that [`ProverState`][`crate::ProverState`] or [`VerifierState`][`crate::VerifierState`] instances can generate successfully a protocol transcript respecting the length constraint but not the types. See [issue #6](https://github.com/arkworks-rs/spongefish/issues/6) for a discussion on the topic.
#[derive(Clone)]
pub struct DomainSeparator<H = crate::DefaultHash, U = u8>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    /// Encoded domain separator string representing the sequence of sponge operations.
    io: String,
    /// Marker for the sponge hash function and unit type used.
    _hash: PhantomData<(H, U)>,
}

/// Sponge operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    /// Indicates absorption of `usize` lanes.
    ///
    /// In a tag, absorb is indicated with 'A'.
    Absorb(usize),
    /// Indicates processing of out-of-band message
    /// from prover to verifier.
    ///
    /// This is useful for e.g. adding merkle proofs to the proof.
    Hint,
    /// Indicates squeezing of `usize` lanes.
    ///
    /// In a tag, squeeze is indicated with 'S'.
    Squeeze(usize),
    /// Indicates a ratchet operation.
    ///
    /// For sponge functions, we squeeze sizeof(capacity) lanes
    /// and initialize a new state filling the capacity.
    /// This allows for a more efficient preprocessing, and for removal of
    /// private information stored in the rate.
    Ratchet,
}

impl Op {
    /// Create a new OP from the portion of a tag.
    fn new(id: char, count: Option<usize>) -> Result<Self, DomainSeparatorMismatch> {
        match (id, count) {
            ('A', Some(c)) if c > 0 => Ok(Self::Absorb(c)),
            ('H', None | Some(0)) => Ok(Self::Hint),
            ('R', None | Some(0)) => Ok(Self::Ratchet),
            ('S', Some(c)) if c > 0 => Ok(Self::Squeeze(c)),
            _ => Err("Invalid tag".into()),
        }
    }
}

impl<H: DuplexSpongeInterface<U>, U: Unit> DomainSeparator<H, U> {
    #[must_use]
    pub const fn from_string(io: String) -> Self {
        Self {
            io,
            _hash: PhantomData,
        }
    }

    /// Create a new DomainSeparator with the domain separator.
    #[must_use]
    pub fn new(session_identifier: &str) -> Self {
        assert!(
            !session_identifier.contains(SEP_BYTE),
            "Domain separator cannot contain the separator BYTE."
        );
        Self::from_string(session_identifier.to_string())
    }

    /// Absorb `count` native elements.
    #[must_use]
    pub fn absorb(self, count: usize, label: &str) -> Self {
        assert!(count > 0, "Count must be positive.");
        assert!(
            !label.contains(SEP_BYTE),
            "Label cannot contain the separator BYTE."
        );
        assert!(
            label
                .chars()
                .next()
                .is_none_or(|char| !char.is_ascii_digit()),
            "Label cannot start with a digit."
        );

        Self::from_string(self.io + SEP_BYTE + &format!("A{count}") + label)
    }

    /// Hint `count` native elements.
    #[must_use]
    pub fn hint(self, label: &str) -> Self {
        assert!(
            !label.contains(SEP_BYTE),
            "Label cannot contain the separator BYTE."
        );

        Self::from_string(self.io + SEP_BYTE + "H" + label)
    }

    /// Squeeze `count` native elements.
    #[must_use]
    pub fn squeeze(self, count: usize, label: &str) -> Self {
        assert!(count > 0, "Count must be positive.");
        assert!(
            !label.contains(SEP_BYTE),
            "Label cannot contain the separator BYTE."
        );
        assert!(
            label
                .chars()
                .next()
                .is_none_or(|char| !char.is_ascii_digit()),
            "Label cannot start with a digit."
        );

        Self::from_string(self.io + SEP_BYTE + &format!("S{count}") + label)
    }

    /// Ratchet the state.
    #[must_use]
    pub fn ratchet(self) -> Self {
        Self::from_string(self.io + SEP_BYTE + "R")
    }

    /// Return the domain separator as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.io.as_bytes()
    }

    /// Parse the givern domain separator into a sequence of [`Op`]'s.
    pub(crate) fn finalize(&self) -> VecDeque<Op> {
        // Guaranteed to succeed as instances are all valid domain_separators
        Self::parse_domsep(self.io.as_bytes())
            .expect("Internal error. Please submit issue to m@orru.net")
    }

    fn parse_domsep(domain_separator: &[u8]) -> Result<VecDeque<Op>, DomainSeparatorMismatch> {
        let mut stack = VecDeque::new();

        // skip the domain separator
        for part in domain_separator
            .split(|&b| b == SEP_BYTE.as_bytes()[0])
            .skip(1)
        {
            let next_id = part[0] as char;
            let next_length = part[1..]
                .iter()
                .take_while(|x| x.is_ascii_digit())
                .fold(0, |acc, x| acc * 10 + (x - b'0') as usize);

            // check that next_length != 0 is performed internally on Op::new
            let next_op = Op::new(next_id, Some(next_length))?;
            stack.push_back(next_op);
        }

        // consecutive calls are merged into one
        match stack.pop_front() {
            None => Ok(stack),
            Some(x) => Ok(Self::simplify_stack([x].into(), stack)),
        }
    }

    fn simplify_stack(mut dst: VecDeque<Op>, mut stack: VecDeque<Op>) -> VecDeque<Op> {
        while let Some(next) = stack.pop_front() {
            match (dst.pop_back(), next) {
                (Some(Op::Squeeze(a)), Op::Squeeze(b)) => dst.push_back(Op::Squeeze(a + b)),
                (Some(Op::Absorb(a)), Op::Absorb(b)) => dst.push_back(Op::Absorb(a + b)),
                (Some(prev), next) => {
                    dst.push_back(prev);
                    dst.push_back(next);
                }
                (None, next) => dst.push_back(next),
            }
        }
        dst
    }

    /// Create an [`crate::ProverState`] instance from the domain separator.
    #[must_use]
    pub fn to_prover_state(&self) -> crate::ProverState<H, U, crate::DefaultRng> {
        self.into()
    }

    /// Create a [`crate::VerifierState`] instance from the domain separator and the protocol transcript (bytes).
    #[must_use]
    pub fn to_verifier_state<'a>(&self, transcript: &'a [u8]) -> crate::VerifierState<'a, H, U> {
        crate::VerifierState::new(self, transcript)
    }
}

impl<U: Unit, H: DuplexSpongeInterface<U>> core::fmt::Debug for DomainSeparator<H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ensure that the state isn't accidentally logged
        write!(f, "DomainSeparator({:?})", self.io)
    }
}

impl<H: DuplexSpongeInterface> ByteDomainSeparator for DomainSeparator<H> {
    #[inline]
    fn add_bytes(self, count: usize, label: &str) -> Self {
        self.absorb(count, label)
    }

    fn hint(self, label: &str) -> Self {
        self.hint(label)
    }

    #[inline]
    fn challenge_bytes(self, count: usize, label: &str) -> Self {
        self.squeeze(count, label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefaultHash;

    pub type H = DefaultHash;

    #[test]
    fn test_op_new_invalid_cases() {
        assert!(Op::new('A', Some(0)).is_err()); // absorb with zero
        assert!(Op::new('H', Some(1)).is_err()); // hint with size
        assert!(Op::new('S', Some(0)).is_err()); // squeeze with zero
        assert!(Op::new('X', Some(1)).is_err()); // invalid op char
        assert!(Op::new('R', Some(5)).is_err()); // R doesn't support > 0
        assert!(Op::new('R', Some(0)).is_ok()); // ratchet with 0
        assert!(Op::new('R', None).is_ok()); // ratchet with None
    }

    #[test]
    fn test_domain_separator_new_and_bytes() {
        let ds = DomainSeparator::<H>::new("session");
        assert_eq!(ds.as_bytes(), b"session");
    }

    #[test]
    #[should_panic]
    fn test_new_with_separator_byte_panics() {
        // This should panic because "\0" is forbidden in the session identifier.
        let _ = DomainSeparator::<H>::new("invalid\0session");
    }

    #[test]
    fn test_domain_separator_absorb_and_squeeze() {
        let ds = DomainSeparator::<H>::new("proto")
            .absorb(2, "input")
            .squeeze(1, "challenge");
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Absorb(2), Op::Squeeze(1)]);
    }

    #[test]
    fn test_domain_separator_ratcheting() {
        let ds = DomainSeparator::<H>::new("session").ratchet();
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Ratchet]);
    }

    #[test]
    fn test_absorb_return_value_format() {
        let ds = DomainSeparator::<H>::new("proto").absorb(3, "input");
        let expected_str = "proto\0A3input"; // initial + SEP + absorb op + label
        assert_eq!(ds.as_bytes(), expected_str.as_bytes());
    }

    #[test]
    #[should_panic]
    fn test_absorb_zero_panics() {
        let _ = DomainSeparator::<H>::new("x").absorb(0, "label");
    }

    #[test]
    #[should_panic]
    fn test_label_with_separator_byte_panics() {
        let _ = DomainSeparator::<H>::new("x").absorb(1, "bad\0label");
    }

    #[test]
    #[should_panic]
    fn test_label_starts_with_digit_panics() {
        let _ = DomainSeparator::<H>::new("x").absorb(1, "1label");
    }

    #[test]
    fn test_merge_consecutive_absorbs_and_squeezes() {
        let ds = DomainSeparator::<H>::new("merge")
            .absorb(1, "a")
            .absorb(2, "b")
            .squeeze(3, "c")
            .squeeze(1, "d");
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Absorb(3), Op::Squeeze(4)]);
    }

    #[test]
    fn test_parse_domsep_multiple_ops() {
        let tag = "main\0A1x\0A2y\0S3z\0R\0S2w";
        let ds = DomainSeparator::<H>::from_string(tag.to_string());
        let ops = ds.finalize();
        assert_eq!(
            ops,
            vec![Op::Absorb(3), Op::Squeeze(3), Op::Ratchet, Op::Squeeze(2)]
        );
    }

    #[test]
    fn test_byte_domain_separator_trait_impl() {
        let ds = DomainSeparator::<H>::new("x")
            .add_bytes(1, "a")
            .challenge_bytes(2, "b");
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Absorb(1), Op::Squeeze(2)]);
    }

    #[test]
    fn test_empty_operations() {
        let ds = DomainSeparator::<H>::new("tag");
        let ops = ds.finalize();
        assert!(ops.is_empty());
    }

    #[test]
    fn test_consecutive_ratchets_preserved() {
        let ds = DomainSeparator::<H>::new("r").ratchet().ratchet();
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Ratchet, Op::Ratchet]);
    }

    #[test]
    fn test_unicode_labels() {
        let ds = DomainSeparator::<H>::new("emoji")
            .absorb(1, "🦀")
            .squeeze(1, "🎯");
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Absorb(1), Op::Squeeze(1)]);
    }

    #[test]
    fn test_large_counts_and_labels() {
        let label = "x".repeat(100);
        let ds = DomainSeparator::<H>::new("big")
            .absorb(12345, &label)
            .squeeze(54321, &label);
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Absorb(12345), Op::Squeeze(54321)]);
    }

    #[test]
    fn test_malformed_tag_parsing_fails() {
        // Missing count
        let broken = "proto\0Ax";
        let ds = DomainSeparator::<H>::from_string(broken.to_string());
        let res = DomainSeparator::<H>::parse_domsep(ds.as_bytes());
        assert!(res.is_err());
    }

    #[test]
    fn test_simplify_stack_keeps_unlike_ops() {
        let tag = "test\0A2x\0S3y\0A1z";
        let ds = DomainSeparator::<H>::from_string(tag.to_string());
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Absorb(2), Op::Squeeze(3), Op::Absorb(1)]);
    }

    #[test]
    fn test_round_trip_operations() {
        let ds1 = DomainSeparator::<H>::new("foo")
            .absorb(2, "a")
            .squeeze(3, "b")
            .ratchet();
        let ops1 = ds1.finalize();

        let tag = std::str::from_utf8(ds1.as_bytes()).unwrap();
        let ds2 = DomainSeparator::<H>::from_string(tag.to_string());
        let ops2 = ds2.finalize();

        assert_eq!(ops1, ops2);
    }

    #[test]
    fn test_squeeze_returns_correct_string() {
        let ds = DomainSeparator::<H>::new("proto").squeeze(4, "challenge");
        let expected_str = "proto\0S4challenge";
        assert_eq!(ds.as_bytes(), expected_str.as_bytes());
    }

    #[test]
    #[should_panic]
    fn test_squeeze_zero_count_panics() {
        let _ = DomainSeparator::<H>::new("proto").squeeze(0, "label");
    }

    #[test]
    #[should_panic]
    fn test_squeeze_label_with_null_byte_panics() {
        let _ = DomainSeparator::<H>::new("proto").squeeze(2, "bad\0label");
    }

    #[test]
    #[should_panic]
    fn test_squeeze_label_starts_with_digit_panics() {
        let _ = DomainSeparator::<H>::new("proto").squeeze(2, "1invalid");
    }

    #[test]
    fn test_multiple_squeeze_chaining() {
        let ds = DomainSeparator::<H>::new("proto")
            .squeeze(1, "first")
            .squeeze(2, "second");
        let expected_str = "proto\0S1first\0S2second";
        assert_eq!(ds.as_bytes(), expected_str.as_bytes());
    }

    #[test]
    fn test_ratchet_returns_correct_self() {
        let ds = DomainSeparator::<H>::new("proto");
        let ratcheted = ds.ratchet();
        let expected_str = "proto\0R";
        assert_eq!(ratcheted.as_bytes(), expected_str.as_bytes());
    }

    #[test]
    fn test_finalize_mixed_ops_order_preserved() {
        let tag = "zkp\0A1a\0S1b\0A2c\0S3d\0R\0A4e\0S1f";
        let ds = DomainSeparator::<H>::from_string(tag.to_string());
        let ops = ds.finalize();
        assert_eq!(
            ops,
            vec![
                Op::Absorb(1),
                Op::Squeeze(1),
                Op::Absorb(2),
                Op::Squeeze(3),
                Op::Ratchet,
                Op::Absorb(4),
                Op::Squeeze(1),
            ]
        );
    }

    #[test]
    fn test_finalize_large_values_and_merge() {
        let tag = "main\0A5a\0A10b\0S8c\0S2d";
        let ds = DomainSeparator::<H>::from_string(tag.to_string());
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Absorb(15), Op::Squeeze(10)]);
    }

    #[test]
    fn test_finalize_merge_and_breaks() {
        let tag = "example\0A2x\0A1y\0R\0A3z\0S4u\0S1v";
        let ds = DomainSeparator::<H>::from_string(tag.to_string());
        let ops = ds.finalize();
        assert_eq!(
            ops,
            vec![Op::Absorb(3), Op::Ratchet, Op::Absorb(3), Op::Squeeze(5),]
        );
    }

    #[test]
    fn test_finalize_only_ratchets() {
        let tag = "onlyratchets\0R\0R\0R";
        let ds = DomainSeparator::<H>::from_string(tag.to_string());
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Ratchet, Op::Ratchet, Op::Ratchet]);
    }

    #[test]
    fn test_finalize_complex_merge_boundaries() {
        let tag = "demo\0A1a\0A1b\0S2c\0S2d\0A3e\0S1f\0Hd";
        let ds = DomainSeparator::<H>::from_string(tag.to_string());
        let ops = ds.finalize();
        assert_eq!(
            ops,
            vec![
                Op::Absorb(2),  // A1a + A1b
                Op::Squeeze(4), // S2c + S2d
                Op::Absorb(3),  // A3e
                Op::Squeeze(1), // S1f
                Op::Hint,       // Hd
            ]
        );
    }

    #[test]
    fn test_hint_is_parsed_correctly() {
        let ds = DomainSeparator::<H>::new("hint_test").hint("my_hint");
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Hint]);
    }

    #[test]
    fn test_hint_format_is_correct_in_bytes() {
        let ds = DomainSeparator::<H>::new("proto").hint("my_hint");
        let expected = b"proto\0Hmy_hint";
        assert_eq!(ds.as_bytes(), expected);
    }

    #[test]
    #[should_panic]
    fn test_hint_label_with_null_byte_panics() {
        let _ = DomainSeparator::<H>::new("x").hint("bad\0hint");
    }

    #[test]
    fn test_hint_combined_with_absorb_and_squeeze() {
        let ds = DomainSeparator::<H>::new("combo")
            .absorb(1, "x")
            .hint("meta")
            .squeeze(2, "y");
        let ops = ds.finalize();
        assert_eq!(ops, vec![Op::Absorb(1), Op::Hint, Op::Squeeze(2)]);
    }
}
