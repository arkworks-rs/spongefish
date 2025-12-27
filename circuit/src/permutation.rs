//! Builders for permutation evaluation relations.
use alloc::{sync::Arc, vec::Vec};

use spin::RwLock;
use spongefish::{Permutation, Unit};

use crate::allocator::{FieldVar, VarAllocator};

/// A [`PermutationInstanceBuilder`] allows to build a relation for
/// evaluations of a permutation acting over WIDTH elements.
#[derive(Clone)]
pub struct PermutationInstanceBuilder<T, const WIDTH: usize> {
    allocator: VarAllocator<T>,
    constraints: Arc<RwLock<PermutationInstance<WIDTH>>>,
}

type QueryAnswerPair<U, const WIDTH: usize> = ([U; WIDTH], [U; WIDTH]);

#[derive(Clone)]
pub struct PermutationWitnessBuilder<P: Permutation<WIDTH>, const WIDTH: usize> {
    trace: Arc<RwLock<Vec<QueryAnswerPair<P::U, WIDTH>>>>,
    permutation: P,
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

impl<P: Permutation<WIDTH>, const WIDTH: usize> Permutation<WIDTH>
    for PermutationWitnessBuilder<P, WIDTH>
{
    type U = P::U;

    fn permute(&self, state: &[Self::U; WIDTH]) -> [Self::U; WIDTH] {
        self.allocate_permutation(state)
    }
}

impl<T: Clone + Unit, const WIDTH: usize> Default for PermutationInstanceBuilder<T, WIDTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Unit, const WIDTH: usize> PermutationInstanceBuilder<T, WIDTH> {
    #[must_use]
    pub fn with_allocator(allocator: VarAllocator<T>) -> Self {
        Self {
            allocator,
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
        self.constraints.write().state.push((input, output));
        output
    }

    pub fn add_permutation(&self, input: [FieldVar; WIDTH], output: [FieldVar; WIDTH]) {
        self.constraints.write().state.push((input, output));
    }

    #[must_use]
    pub fn constraints(&self) -> impl AsRef<[([FieldVar; WIDTH], [FieldVar; WIDTH])]> {
        self.constraints.read().state.clone()
    }

    #[must_use]
    pub fn public_vars(&self) -> Vec<(FieldVar, T)> {
        self.allocator.public_vars()
    }
}

impl<P: Permutation<WIDTH>, const WIDTH: usize> From<P> for PermutationWitnessBuilder<P, WIDTH> {
    fn from(value: P) -> Self {
        Self::new(value)
    }
}

impl<P: Permutation<WIDTH>, const WIDTH: usize> PermutationWitnessBuilder<P, WIDTH> {
    #[must_use]
    pub fn new(permutation: P) -> Self {
        Self {
            trace: Default::default(),
            permutation,
        }
    }

    #[must_use]
    pub fn allocate_permutation(&self, input: &[P::U; WIDTH]) -> [P::U; WIDTH] {
        let output = self.permutation.permute(input);
        self.add_permutation(input, &output);
        output
    }

    pub fn add_permutation(&self, input: &[P::U; WIDTH], output: &[P::U; WIDTH]) {
        self.trace.write().push((input.clone(), output.clone()));
    }

    #[must_use]
    pub fn trace(&self) -> impl AsRef<[QueryAnswerPair<P::U, WIDTH>]> {
        self.trace.read().clone()
    }
}
