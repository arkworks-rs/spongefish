//! Builders for permutation evaluation relations.
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

use spongefish::{Permutation, Unit};

use crate::allocator::{FieldVar, VarAllocator};

/// A [`PermutationInstanceBuilder`] allows to build a relation for
/// evaluations of a permutation acting over WIDTH elements.
#[derive(Clone)]
pub struct PermutationInstanceBuilder<T, const WIDTH: usize> {
    allocator: VarAllocator<T>,
    constraints: Rc<RefCell<PermutationInstance<WIDTH>>>,
}

/// The internal state of the instance,
/// holding the input-output pairs of the wires to be proven.
#[derive(Clone, Default)]
struct PermutationInstance<const WIDTH: usize> {
    state: Vec<([FieldVar; WIDTH], [FieldVar; WIDTH])>,
}

impl<T: Unit, const WIDTH: usize> Permutation<WIDTH> for PermutationInstanceBuilder<T, WIDTH> {
    type U = FieldVar;

    fn permute(&self, state: &[Self::U; WIDTH]) -> [Self::U; WIDTH] {
        self.allocate_permutation(state)
    }
}

impl<T: Clone, const WIDTH: usize> Default for PermutationInstanceBuilder<T, WIDTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone, const WIDTH: usize> PermutationInstanceBuilder<T, WIDTH> {
    #[must_use] 
    pub fn with_allocator(allocator: VarAllocator<T>) -> Self {
        Self {
            allocator: allocator,
            constraints: Default::default(),
        }
    }

    #[must_use] 
    pub fn new() -> Self {
        Self::with_allocator(VarAllocator::new())
    }

    #[must_use] 
    pub const fn allocator(&self) -> &VarAllocator<T> {
        &self.allocator
    }

    #[must_use] 
    pub fn allocate_permutation(&self, &input: &[FieldVar; WIDTH]) -> [FieldVar; WIDTH] {
        let output = self.allocator.allocate_vars();
        self.constraints.borrow_mut().state.push((input, output));
        output
    }

    pub fn add_permutation(&self, input: [FieldVar; WIDTH], output: [FieldVar; WIDTH]) {
        self.constraints.borrow_mut().state.push((input, output));
    }

    #[must_use] 
    pub fn constraints(&self) -> impl AsRef<[([FieldVar; WIDTH], [FieldVar; WIDTH])]> {
        self.constraints.borrow_mut().state.clone()
    }

    #[must_use] 
    pub fn public_vars(&self) -> Vec<(FieldVar, T)> {
        self.allocator.public_vars()
    }
}
