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
    linear_constraints: Arc<RwLock<LinearConstraints<FieldVar, T>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearEquation<T, U> {
    /// Coefficient-variable pairs representing the left-hand side of
    /// `sum_i coefficient_i * variable_i = image`.
    pub linear_combination: Vec<(U, T)>,
    /// The right-hand side of the linear relation.
    pub image: U,
}

impl<T, U> LinearEquation<T, U> {
    #[must_use]
    pub fn new(linear_combination: impl IntoIterator<Item = (U, T)>, image: U) -> Self {
        Self {
            linear_combination: linear_combination.into_iter().collect(),
            image,
        }
    }
}

impl<T, U: Unit> Default for LinearEquation<T, U> {
    fn default() -> Self {
        Self {
            linear_combination: Vec::new(),
            image: U::ZERO,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearConstraints<T, U> {
    pub equations: Vec<LinearEquation<T, U>>,
}

impl<T, U> AsRef<[LinearEquation<T, U>]> for LinearConstraints<T, U> {
    fn as_ref(&self) -> &[LinearEquation<T, U>] {
        &self.equations
    }
}

impl<T, U> Default for LinearConstraints<T, U> {
    fn default() -> Self {
        Self {
            equations: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryAnswerPair<T, const WIDTH: usize> {
    pub input: [T; WIDTH],
    pub output: [T; WIDTH],
}

impl<T, const WIDTH: usize> QueryAnswerPair<T, WIDTH> {
    #[must_use]
    pub const fn new(input: [T; WIDTH], output: [T; WIDTH]) -> Self {
        Self { input, output }
    }
}

#[derive(Clone)]
pub struct PermutationWitnessBuilder<P: Permutation<WIDTH>, const WIDTH: usize> {
    permutation: P,
    trace: Arc<RwLock<Vec<QueryAnswerPair<P::U, WIDTH>>>>,
    linear_constraints: Arc<RwLock<LinearConstraints<P::U, P::U>>>,
}

/// The internal state of the instance,
/// holding the input-output pairs of the wires to be proven.
#[derive(Clone, Default)]
struct PermutationInstance<const WIDTH: usize> {
    state: Vec<QueryAnswerPair<FieldVar, WIDTH>>,
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
            .push(QueryAnswerPair::new(input, output));
    }

    pub fn add_equation(&self, equation: LinearEquation<FieldVar, T>) {
        self.linear_constraints.write().equations.push(equation);
    }

    #[must_use]
    pub fn constraints(&self) -> impl AsRef<[QueryAnswerPair<FieldVar, WIDTH>]> {
        self.permutation_constraints.read().state.clone()
    }

    #[must_use]
    pub fn linear_constraints(&self) -> LinearConstraints<FieldVar, T> {
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
        self.trace
            .write()
            .push(QueryAnswerPair::new(input.clone(), output.clone()));
    }

    pub fn add_equation(&self, equation: LinearEquation<P::U, P::U>) {
        self.linear_constraints.write().equations.push(equation);
    }

    #[must_use]
    pub fn trace(&self) -> impl AsRef<[QueryAnswerPair<P::U, WIDTH>]> {
        self.trace.read().clone()
    }

    #[must_use]
    pub fn linear_constraints(&self) -> LinearConstraints<P::U, P::U> {
        self.linear_constraints.read().clone()
    }
}
