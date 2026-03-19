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
    permutation_constraints: Arc<RwLock<PermutationInstance<WIDTH>>>,
    linear_constraints: Arc<RwLock<LinearConstraints<FieldVar>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearEquation<T> {
    pub linear_combination: Vec<T>,
}

impl<T> LinearEquation<T> {
    #[must_use]
    pub fn new(terms: impl IntoIterator<Item = T>) -> Self {
        Self {
            linear_combination: terms.into_iter().collect(),
        }
    }
}

impl<T> Default for LinearEquation<T> {
    fn default() -> Self {
        Self {
            linear_combination: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearConstraints<T> {
    pub equations: Vec<LinearEquation<T>>,
}

impl<T> AsRef<[LinearEquation<T>]> for LinearConstraints<T> {
    fn as_ref(&self) -> &[LinearEquation<T>] {
        &self.equations
    }
}

impl<T> Default for LinearConstraints<T> {
    fn default() -> Self {
        Self {
            equations: Vec::new(),
        }
    }
}

type QueryAnswerPair<U, const WIDTH: usize> = ([U; WIDTH], [U; WIDTH]);

#[derive(Clone)]
pub struct PermutationWitnessBuilder<P: Permutation<WIDTH>, const WIDTH: usize> {
    permutation: P,
    trace: Arc<RwLock<Vec<QueryAnswerPair<P::U, WIDTH>>>>,
    linear_constraints: Arc<RwLock<LinearConstraints<P::U>>>,
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
            permutation_constraints: Default::default(),
            linear_constraints: Default::default(),
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
        self.add_permutation(input, output);
        output
    }

    pub fn add_permutation(&self, input: [FieldVar; WIDTH], output: [FieldVar; WIDTH]) {
        self.permutation_constraints
            .write()
            .state
            .push((input, output));
    }

    pub fn add_equation(&self, equation: LinearEquation<FieldVar>) {
        self.linear_constraints.write().equations.push(equation);
    }

    #[must_use]
    pub fn constraints(&self) -> impl AsRef<[([FieldVar; WIDTH], [FieldVar; WIDTH])]> {
        self.permutation_constraints.read().state.clone()
    }

    #[must_use]
    pub fn linear_constraints(&self) -> LinearConstraints<FieldVar> {
        self.linear_constraints.read().clone()
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
            permutation,
            trace: Default::default(),
            linear_constraints: Default::default(),
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

    pub fn add_equation(&self, equation: LinearEquation<P::U>) {
        self.linear_constraints.write().equations.push(equation);
    }

    #[must_use]
    pub fn trace(&self) -> impl AsRef<[QueryAnswerPair<P::U, WIDTH>]> {
        self.trace.read().clone()
    }

    #[must_use]
    pub fn linear_constraints(&self) -> LinearConstraints<P::U> {
        self.linear_constraints.read().clone()
    }
}
