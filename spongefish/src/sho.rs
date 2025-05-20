use core::{fmt, marker::PhantomData};
use std::collections::vec_deque::VecDeque;

use super::{
    domain_separator::{DomainSeparator, Op},
    duplex_sponge::{DuplexSpongeInterface, Unit},
    errors::DomainSeparatorMismatch,
    keccak::Keccak,
};

/// A stateful hash object that interfaces with duplex interfaces.
#[derive(Clone)]
pub struct HashStateWithInstructions<H, U = u8>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    /// The internal duplex sponge used for absorbing and squeezing data.
    ds: H,
    /// A stack of expected sponge operations.
    stack: VecDeque<Op>,
    /// Marker to associate the unit type `U` without storing a value.
    _unit: PhantomData<U>,
}

impl<U: Unit, H: DuplexSpongeInterface<U>> HashStateWithInstructions<H, U> {
    /// Initialise a stateful hash object,
    /// setting up the state of the sponge function and parsing the tag string.
    #[must_use]
    pub fn new(domain_separator: &DomainSeparator<H, U>) -> Self {
        let stack = domain_separator.finalize();
        let tag = Self::generate_tag(domain_separator.as_bytes());
        Self::unchecked_load_with_stack(tag, stack)
    }

    /// Finish the block and compress the state.
    pub fn ratchet(&mut self) -> Result<(), DomainSeparatorMismatch> {
        match self.stack.pop_front() {
            Some(Op::Ratchet) => {
                self.ds.ratchet_unchecked();
                Ok(())
            }
            Some(op) => Err(format!("Expected Ratchet, got {op:?}").into()),
            None => Err("Expected Ratchet, but stack is empty".into()),
        }
    }

    /// Ratchet and return the sponge state.
    pub fn preprocess(self) -> Result<&'static [U], DomainSeparatorMismatch> {
        unimplemented!()
        // self.ratchet()?;
        // Ok(self.sponge.tag().clone())
    }

    /// Perform secure absorption of the elements in `input`.
    ///
    /// Absorb calls can be batched together, or provided separately for streaming-friendly protocols.
    pub fn absorb(&mut self, input: &[U]) -> Result<(), DomainSeparatorMismatch> {
        match self.stack.pop_front() {
            Some(Op::Absorb(length)) if length >= input.len() => {
                if length > input.len() {
                    self.stack.push_front(Op::Absorb(length - input.len()));
                }
                self.ds.absorb_unchecked(input);
                Ok(())
            }
            None => {
                self.stack.clear();
                Err(format!(
                    "Invalid tag. Stack empty, got {:?}",
                    Op::Absorb(input.len())
                )
                .into())
            }
            Some(op) => {
                self.stack.clear();
                Err(format!(
                    "Invalid tag. Got {:?}, expected {:?}",
                    Op::Absorb(input.len()),
                    op
                )
                .into())
            }
        }
    }

    /// Send or receive a hint from the proof stream.
    pub fn hint(&mut self) -> Result<(), DomainSeparatorMismatch> {
        match self.stack.pop_front() {
            Some(Op::Hint) => Ok(()),
            Some(op) => Err(format!("Invalid tag. Got Op::Hint, expected {op:?}",).into()),
            None => Err(format!("Invalid tag. Stack empty, got {:?}", Op::Hint).into()),
        }
    }

    /// Perform a secure squeeze operation, filling the output buffer with uniformly random bytes.
    ///
    /// For byte-oriented sponges, this operation is equivalent to the squeeze operation.
    /// However, for algebraic hashes, this operation is non-trivial.
    /// This function provides no guarantee of streaming-friendliness.
    pub fn squeeze(&mut self, output: &mut [U]) -> Result<(), DomainSeparatorMismatch> {
        match self.stack.pop_front() {
            Some(Op::Squeeze(length)) if output.len() <= length => {
                self.ds.squeeze_unchecked(output);
                if length != output.len() {
                    self.stack.push_front(Op::Squeeze(length - output.len()));
                }
                Ok(())
            }
            None => {
                self.stack.clear();
                Err(format!(
                    "Invalid tag. Stack empty, got {:?}",
                    Op::Squeeze(output.len())
                )
                .into())
            }
            Some(op) => {
                self.stack.clear();
                Err(format!(
                    "Invalid tag. Got {:?}, expected {:?}. The stack remaining is: {:?}",
                    Op::Squeeze(output.len()),
                    op,
                    self.stack
                )
                .into())
            }
        }
    }

    fn generate_tag(iop_bytes: &[u8]) -> [u8; 32] {
        let mut keccak = Keccak::default();
        keccak.absorb_unchecked(iop_bytes);
        let mut tag = [0u8; 32];
        keccak.squeeze_unchecked(&mut tag);
        tag
    }

    fn unchecked_load_with_stack(tag: [u8; 32], stack: VecDeque<Op>) -> Self {
        Self {
            ds: H::new(tag),
            stack,
            _unit: PhantomData,
        }
    }

    #[cfg(test)]
    pub const fn ds(&self) -> &H {
        &self.ds
    }
}

impl<U: Unit, H: DuplexSpongeInterface<U>> Drop for HashStateWithInstructions<H, U> {
    /// Destroy the sponge state.
    fn drop(&mut self) {
        // it's a bit violent to panic here,
        // because any other issue in the protocol transcript causing `Safe` to get out of scope
        // (like another panic) will pollute the traceback.
        // debug_assert!(self.stack.is_empty());
        if !self.stack.is_empty() {
            eprintln!("Unfinished operations:\n {:?}", self.stack);
        }
        // XXX. is the compiler going to optimize this out?
        self.ds.zeroize();
    }
}

impl<U: Unit, H: DuplexSpongeInterface<U>> fmt::Debug for HashStateWithInstructions<H, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ensure that the state isn't accidentally logged,
        // but provide the remaining domain separator for debugging.
        write!(
            f,
            "Sponge in duplex mode with committed verifier operations: {:?}",
            self.stack
        )
    }
}

impl<U: Unit, H: DuplexSpongeInterface<U>, B: core::borrow::Borrow<DomainSeparator<H, U>>> From<B>
    for HashStateWithInstructions<H, U>
{
    fn from(value: B) -> Self {
        Self::new(value.borrow())
    }
}

#[cfg(test)]
#[allow(clippy::bool_assert_comparison)]
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
                *byte = i as u8; // Dummy output
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
    fn test_absorb_works_and_modifies_stack() {
        let domsep = DomainSeparator::<DummySponge>::new("test").absorb(2, "x");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        assert_eq!(state.stack.len(), 1);

        let result = state.absorb(&[1, 2]);
        assert!(result.is_ok());

        assert_eq!(state.stack.len(), 0);
        let inner = state.ds.absorbed.borrow();
        assert_eq!(&*inner, &[1, 2]);
    }

    #[test]
    fn test_absorb_too_much_returns_error() {
        let domsep = DomainSeparator::<DummySponge>::new("test").absorb(2, "x");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        let result = state.absorb(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_squeeze_works() {
        let domsep = DomainSeparator::<DummySponge>::new("test").squeeze(3, "y");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        let mut out = [0u8; 3];
        let result = state.squeeze(&mut out);
        assert!(result.is_ok());
        assert_eq!(out, [0, 1, 2]);
    }

    #[test]
    fn test_squeeze_with_leftover_updates_stack() {
        let domsep = DomainSeparator::<DummySponge>::new("test").squeeze(4, "z");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        let mut out = [0u8; 2];
        let result = state.squeeze(&mut out);
        assert!(result.is_ok());

        assert_eq!(state.stack.front(), Some(&Op::Squeeze(2)));
    }

    #[test]
    fn test_ratchet_correct_op() {
        let domsep = DomainSeparator::<DummySponge>::new("test").ratchet();
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        let result = state.ratchet();
        assert!(result.is_ok());
        assert_eq!(*state.ds.ratcheted.borrow(), true);
    }

    #[test]
    fn test_ratchet_wrong_op_returns_error() {
        let domsep = DomainSeparator::<DummySponge>::new("test").absorb(1, "oops");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        let result = state.ratchet();
        assert!(result.is_err());
        assert!(state.stack.is_empty());
    }

    #[test]
    fn test_multiple_absorbs_deplete_stack_properly() {
        let domsep = DomainSeparator::<DummySponge>::new("test").absorb(5, "a");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        let res1 = state.absorb(&[1, 2]);
        assert!(res1.is_ok());
        assert_eq!(state.stack.front(), Some(&Op::Absorb(3)));

        let res2 = state.absorb(&[3, 4, 5]);
        assert!(res2.is_ok());
        assert!(state.stack.is_empty());

        assert_eq!(&*state.ds.absorbed.borrow(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_multiple_squeeze_deplete_stack_properly() {
        let domsep = DomainSeparator::<DummySponge>::new("test").squeeze(5, "z");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        let mut out1 = [0u8; 2];
        assert!(state.squeeze(&mut out1).is_ok());
        assert_eq!(state.stack.front(), Some(&Op::Squeeze(3)));

        let mut out2 = [0u8; 3];
        assert!(state.squeeze(&mut out2).is_ok());
        assert!(state.stack.is_empty());
        assert_eq!(&*state.ds.squeezed.borrow(), &[0, 1, 0, 1, 2]);
    }

    #[test]
    fn test_absorb_then_wrong_squeeze_clears_stack() {
        let domsep = DomainSeparator::<DummySponge>::new("test").absorb(3, "in");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        let mut out = [0u8; 1];
        let result = state.squeeze(&mut out);
        assert!(result.is_err());
        assert!(state.stack.is_empty());
    }

    #[test]
    fn test_absorb_exact_then_too_much() {
        let domsep = DomainSeparator::<DummySponge>::new("test").absorb(2, "x");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        assert!(state.absorb(&[10, 20]).is_ok());
        assert!(state.absorb(&[30]).is_err()); // no ops left
        assert!(state.stack.is_empty());
    }

    #[test]
    fn test_from_impl_constructs_hash_state() {
        let domsep = DomainSeparator::<DummySponge>::new("from").absorb(1, "in");
        let state = HashStateWithInstructions::<DummySponge>::from(&domsep);

        assert_eq!(state.stack.len(), 1);
        assert_eq!(state.stack.front(), Some(&Op::Absorb(1)));
    }

    #[test]
    fn test_generate_tag_is_deterministic() {
        let ds1 = DomainSeparator::<DummySponge>::new("session1").absorb(1, "x");
        let ds2 = DomainSeparator::<DummySponge>::new("session1").absorb(1, "x");

        let tag1 = HashStateWithInstructions::<DummySponge>::new(&ds1);
        let tag2 = HashStateWithInstructions::<DummySponge>::new(&ds2);

        assert_eq!(&*tag1.ds.absorbed.borrow(), &*tag2.ds.absorbed.borrow());
    }

    #[test]
    fn test_hint_works_and_removes_stack_entry() {
        let domsep = DomainSeparator::<DummySponge>::new("test").hint("hint");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        assert_eq!(state.stack.len(), 1);
        let result = state.hint();
        assert!(result.is_ok());
        assert!(state.stack.is_empty());
    }

    #[test]
    fn test_hint_wrong_op_errors_and_clears_stack() {
        let domsep = DomainSeparator::<DummySponge>::new("test").absorb(1, "x");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        let result = state.hint(); // Should expect Op::Hint, but see Op::Absorb
        assert!(result.is_err());
        assert!(state.stack.is_empty());
    }

    #[test]
    fn test_hint_on_empty_stack_errors() {
        let domsep = DomainSeparator::<DummySponge>::new("test");
        let mut state = HashStateWithInstructions::<DummySponge>::new(&domsep);

        let result = state.hint(); // Stack is empty
        assert!(result.is_err());
    }
}
