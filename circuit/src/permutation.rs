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
    query_answers: Arc<RwLock<Vec<QueryAnswerPair<FieldVar, WIDTH>>>>,
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

/// An immutable snapshot of a permutation relation instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermutationInstance<T, const WIDTH: usize> {
    pub vars_count: usize,
    pub public_values: Vec<(FieldVar, T)>,
    /// The input-output wires to be proven
    pub query_answers: Vec<QueryAnswerPair<FieldVar, WIDTH>>,
    pub linear_constraints: LinearConstraints<FieldVar, T>,
}

impl<T, const WIDTH: usize> PermutationInstance<T, WIDTH> {
    #[must_use]
    pub fn constraints(&self) -> impl AsRef<[QueryAnswerPair<FieldVar, WIDTH>]> + '_ {
        &self.query_answers
    }

    #[must_use]
    pub const fn linear_constraints(&self) -> &LinearConstraints<FieldVar, T> {
        &self.linear_constraints
    }

    #[must_use]
    pub fn public_vars(&self) -> &[(FieldVar, T)] {
        &self.public_values
    }
}

/// An immutable snapshot of a permutation witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermutationWitness<T, const WIDTH: usize> {
    pub trace: Vec<QueryAnswerPair<T, WIDTH>>,
    pub linear_constraints: LinearConstraints<T, T>,
}

impl<T, const WIDTH: usize> PermutationWitness<T, WIDTH> {
    #[must_use]
    pub fn trace(&self) -> impl AsRef<[QueryAnswerPair<T, WIDTH>]> + '_ {
        &self.trace
    }

    #[must_use]
    pub const fn linear_constraints(&self) -> &LinearConstraints<T, T> {
        &self.linear_constraints
    }
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
            query_answers: Default::default(),
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
        debug_assert!(input
            .iter()
            .chain(output.iter())
            .all(|var| self.allocator.is_allocated(*var)));
        self.query_answers
            .write()
            .push(QueryAnswerPair::new(input, output));
    }

    pub fn add_equation(&self, equation: LinearEquation<FieldVar, T>)
    where
        T: PartialEq,
    {
        let constraints = self.query_answers.read();
        for (_, var) in &equation.linear_combination {
            assert!(
                self.allocator.is_allocated(*var),
                "unallocated variable {}",
                var.index(),
            );
        }
        for (term_idx, (coeff, var)) in equation.linear_combination.iter().enumerate() {
            if *coeff == T::ZERO {
                continue;
            }
            assert!(
                constraints
                    .iter()
                    .flat_map(|pair| pair.input.iter().chain(pair.output.iter()))
                    .any(|known_var| known_var == var),
                "linear equation term {term_idx} references variable {}, \
                 but nonzero linear terms must reference a permutation input or output variable",
                var.index(),
            );
        }
        self.linear_constraints.write().equations.push(equation);
    }

    #[must_use]
    pub fn constraints(&self) -> impl AsRef<[QueryAnswerPair<FieldVar, WIDTH>]> {
        self.query_answers.read().clone()
    }

    #[must_use]
    pub fn linear_constraints(&self) -> LinearConstraints<FieldVar, T> {
        self.linear_constraints.read().clone()
    }

    #[must_use]
    pub fn public_vars(&self) -> Vec<(FieldVar, T)> {
        self.allocator.public_vars()
    }

    #[must_use]
    pub fn snapshot(&self) -> PermutationInstance<T, WIDTH> {
        PermutationInstance {
            vars_count: self.allocator.vars_count(),
            public_values: self.allocator.public_vars(),
            query_answers: self.constraints().as_ref().to_vec(),
            linear_constraints: self.linear_constraints(),
        }
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

    #[must_use]
    pub fn snapshot(&self) -> PermutationWitness<P::U, WIDTH> {
        PermutationWitness {
            trace: self.trace().as_ref().to_vec(),
            linear_constraints: self.linear_constraints(),
        }
    }
}
