//! Relations over evaluations of a permutation, and the witnesses proving them.
//!
//! A [`PermutationRelation`] is a [`Permutation`] over wires: each call it
//! receives is recorded as a query, the pair of input and output wires, and
//! becomes one constraint of the [`PermutationInstance`] it compiles to. A
//! [`PermutationWitnessBuilder`] wraps the concrete permutation and records
//! the values that flowed through the same calls, the trace that is the
//! [`PermutationWitness`]. Code written once against
//! [`DuplexSpongeInterface`][spongefish::DuplexSpongeInterface] runs over
//! either.

use alloc::{format, string::String, sync::Arc, vec::Vec};

use spin::RwLock;
use spongefish::{Permutation, Unit};

use crate::{
    allocator::{FieldVar, VarAllocator},
    error::InvalidRelation,
    expr::{Ring, Sum},
};

/// One evaluation of the permutation: the state it read and the state it
/// wrote. Over wires in a relation, over values in a witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryAnswerPair<U, const WIDTH: usize> {
    pub input: [U; WIDTH],
    pub output: [U; WIDTH],
}

impl<U, const WIDTH: usize> QueryAnswerPair<U, WIDTH> {
    pub const fn new(input: [U; WIDTH], output: [U; WIDTH]) -> Self {
        Self { input, output }
    }
}

/// The equation `Σ weight_i · var_i = image`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearEquation<T> {
    /// The left-hand side.
    pub terms: Sum<T>,
    /// The constant the sum must equal.
    pub image: T,
}

impl<T> LinearEquation<T> {
    pub fn new(terms: impl Into<Sum<T>>, image: T) -> Self {
        Self {
            terms: terms.into(),
            image,
        }
    }
}

/// A relation over evaluations of a permutation acting on `WIDTH` wires.
///
/// Handles are reference counted: cloning one, as
/// [`DuplexSponge::from`][spongefish::DuplexSponge] does, shares the relation
/// rather than forking it, so the queries a sponge makes are visible on every
/// handle.
///
/// ```
/// use spongefish::{DuplexSponge, DuplexSpongeInterface};
/// use spongefish_circuit::PermutationRelation;
///
/// let relation = PermutationRelation::<u32, 4>::new();
/// let public = relation.allocate_vars_with(&[1, 2]);
/// let secret = relation.allocate_vars::<2>();
///
/// let mut sponge = DuplexSponge::<_, 4, 2>::from(relation.clone());
/// let [digest] = sponge.absorb(&public).absorb(&secret).squeeze_array();
/// relation.set_var(digest, 42);
///
/// let instance = relation.compile().unwrap();
/// assert_eq!(instance.queries().len(), 2);
/// ```
pub struct PermutationRelation<T, const WIDTH: usize> {
    label: String,
    allocator: VarAllocator<T>,
    queries: Arc<RwLock<Vec<QueryAnswerPair<FieldVar, WIDTH>>>>,
    equations: Arc<RwLock<Vec<LinearEquation<T>>>>,
}

impl<T, const WIDTH: usize> Clone for PermutationRelation<T, WIDTH> {
    fn clone(&self) -> Self {
        Self {
            label: self.label.clone(),
            allocator: self.allocator.clone(),
            queries: Arc::clone(&self.queries),
            equations: Arc::clone(&self.equations),
        }
    }
}

impl<T: Unit, const WIDTH: usize> Default for PermutationRelation<T, WIDTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Unit, const WIDTH: usize> PermutationRelation<T, WIDTH> {
    /// An unlabeled relation over a fresh [`VarAllocator`].
    pub fn new() -> Self {
        Self::with_allocator(VarAllocator::new())
    }

    /// A relation naming its permutation, such as `keccak-f[1600]`.
    ///
    /// The label travels with the compiled instance and its byte encoding,
    /// so a proof system can check it is being handed the permutation it
    /// implements. It is free text; the relation does not interpret it.
    pub fn labeled(label: impl Into<String>) -> Self {
        let mut relation = Self::new();
        relation.label = label.into();
        relation
    }

    /// A relation sharing `allocator` with other relations.
    pub fn with_allocator(allocator: VarAllocator<T>) -> Self {
        Self {
            label: String::new(),
            allocator,
            queries: Arc::default(),
            equations: Arc::default(),
        }
    }

    /// The permutation's label, empty unless set by [`Self::labeled`].
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The allocator, for sharing wires with another relation.
    pub const fn allocator(&self) -> &VarAllocator<T> {
        &self.allocator
    }

    /// See [`VarAllocator::allocate_var`].
    pub fn allocate_var(&self) -> FieldVar {
        self.allocator.allocate_var()
    }

    /// See [`VarAllocator::allocate_vars`].
    pub fn allocate_vars<const N: usize>(&self) -> [FieldVar; N] {
        self.allocator.allocate_vars()
    }

    /// See [`VarAllocator::allocate_vars_vec`].
    pub fn allocate_vars_vec(&self, count: usize) -> Vec<FieldVar> {
        self.allocator.allocate_vars_vec(count)
    }

    /// See [`VarAllocator::allocate_var_with`].
    pub fn allocate_var_with(&self, value: T) -> FieldVar
    where
        T: PartialEq,
    {
        self.allocator.allocate_var_with(value)
    }

    /// See [`VarAllocator::allocate_vars_with`].
    pub fn allocate_vars_with<const N: usize>(&self, values: &[T; N]) -> [FieldVar; N]
    where
        T: PartialEq,
    {
        self.allocator.allocate_vars_with(values)
    }

    /// See [`VarAllocator::allocate_vars_vec_with`].
    pub fn allocate_vars_vec_with(&self, values: &[T]) -> Vec<FieldVar>
    where
        T: PartialEq,
    {
        self.allocator.allocate_vars_vec_with(values)
    }

    /// See [`VarAllocator::set_var`].
    pub fn set_var(&self, var: FieldVar, value: T)
    where
        T: PartialEq,
    {
        self.allocator.set_var(var, value);
    }

    /// See [`VarAllocator::set_vars`].
    pub fn set_vars<Var, Val>(
        &self,
        vars: impl IntoIterator<Item = Var>,
        values: impl IntoIterator<Item = Val>,
    ) where
        Var: core::borrow::Borrow<FieldVar>,
        Val: core::borrow::Borrow<T>,
        T: PartialEq,
    {
        self.allocator.set_vars(vars, values);
    }

    /// Records a query of the permutation on `input`, returning fresh output
    /// wires.
    pub fn allocate_permutation(&self, input: &[FieldVar; WIDTH]) -> [FieldVar; WIDTH] {
        let output = self.allocate_vars();
        self.add_permutation(*input, output);
        output
    }

    /// Records that the permutation maps `input` to `output`.
    pub fn add_permutation(&self, input: [FieldVar; WIDTH], output: [FieldVar; WIDTH]) {
        self.queries
            .write()
            .push(QueryAnswerPair::new(input, output));
    }

    /// Adds the equation `terms = image`.
    ///
    /// Terms are built with the operators on [`FieldVar`]: `x * a + y * b + z`
    /// weights `x` by `a`, `y` by `b`, and `z` by one. Every wire with a
    /// nonzero weight must be an input or output of some query, or be
    /// assigned; [`Self::compile`] rejects the equation otherwise, as nothing
    /// else would fix the wire's value.
    pub fn add_equation(&self, terms: impl Into<Sum<T>>, image: T) {
        self.equations
            .write()
            .push(LinearEquation::new(terms, image));
    }

    /// The queries recorded so far.
    pub fn queries(&self) -> Vec<QueryAnswerPair<FieldVar, WIDTH>> {
        self.queries.read().clone()
    }

    /// The equations recorded so far.
    pub fn equations(&self) -> Vec<LinearEquation<T>> {
        self.equations.read().clone()
    }

    /// See [`VarAllocator::public_vars`].
    pub fn public_vars(&self) -> Vec<(FieldVar, T)> {
        self.allocator.public_vars()
    }

    /// Compiles the relation into a validated [`PermutationInstance`].
    ///
    /// Every wire a query or an equation mentions must have been allocated,
    /// and every wire with a nonzero weight in an equation must be bound: an
    /// input or output of some query, or assigned a value. Wires that are
    /// allocated but neither bound nor mentioned are left in place, so wire
    /// indices are the same on both sides of this call.
    pub fn compile(&self) -> Result<PermutationInstance<T, WIDTH>, InvalidRelation>
    where
        T: PartialEq,
    {
        let values = self.allocator.values();
        let vars_count = values.len();
        let public_values = values
            .into_iter()
            .enumerate()
            .filter_map(|(index, value)| Some((FieldVar::try_from_index(index)?, value?)))
            .collect();
        PermutationInstance::validated(
            self.label.clone(),
            vars_count,
            public_values,
            self.queries(),
            self.equations(),
        )
    }
}

impl<T: Unit, const WIDTH: usize> PermutationInstance<T, WIDTH> {
    /// Checks the parts of a relation and assembles the instance; the gate
    /// behind [`PermutationRelation::compile`] and the byte decoder.
    pub(crate) fn validated(
        label: String,
        vars_count: usize,
        public_values: Vec<(FieldVar, T)>,
        queries: Vec<QueryAnswerPair<FieldVar, WIDTH>>,
        equations: Vec<LinearEquation<T>>,
    ) -> Result<Self, InvalidRelation>
    where
        T: PartialEq,
    {
        let mut bound = alloc::vec![false; vars_count];
        for (var, _) in &public_values {
            match bound.get_mut(var.index()) {
                Some(slot) => *slot = true,
                None => {
                    return Err(InvalidRelation::new(format!(
                        "public variable {} is unallocated",
                        var.index()
                    )))
                }
            }
        }
        for (index, query) in queries.iter().enumerate() {
            for var in query.input.iter().chain(&query.output) {
                let Some(slot) = bound.get_mut(var.index()) else {
                    return Err(InvalidRelation::new(format!(
                        "query {index} references unallocated variable {}",
                        var.index()
                    )));
                };
                *slot = true;
            }
        }

        for (index, equation) in equations.iter().enumerate() {
            for term in equation.terms.terms() {
                match bound.get(term.var.index()) {
                    None => {
                        return Err(InvalidRelation::new(format!(
                            "equation {index} references unallocated variable {}",
                            term.var.index()
                        )))
                    }
                    Some(false) if term.weight != T::ZERO => {
                        return Err(InvalidRelation::new(format!(
                            "equation {index} weights variable {}, which no query or \
                             assignment binds",
                            term.var.index()
                        )))
                    }
                    Some(_) => {}
                }
            }
        }

        Ok(Self {
            label,
            vars_count,
            public_values,
            queries,
            equations,
        })
    }
}

impl<T: Unit, const WIDTH: usize> Permutation<WIDTH> for PermutationRelation<T, WIDTH> {
    type U = FieldVar;

    /// A query mints fresh output wires rather than mixing the state in
    /// place, so both maps go through [`Self::allocate_permutation`].
    fn permute_mut(&self, state: &mut [Self::U; WIDTH]) {
        *state = self.allocate_permutation(state);
    }

    fn permute(&self, state: &[Self::U; WIDTH]) -> [Self::U; WIDTH] {
        self.allocate_permutation(state)
    }
}

/// A validated relation, ready for a proof system.
///
/// Produced by [`PermutationRelation::compile`]; see there for what is
/// checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermutationInstance<T, const WIDTH: usize> {
    pub(crate) label: String,
    pub(crate) vars_count: usize,
    pub(crate) public_values: Vec<(FieldVar, T)>,
    pub(crate) queries: Vec<QueryAnswerPair<FieldVar, WIDTH>>,
    pub(crate) equations: Vec<LinearEquation<T>>,
}

impl<T, const WIDTH: usize> PermutationInstance<T, WIDTH> {
    /// The permutation's label; see [`PermutationRelation::labeled`].
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The number of wires, [`FieldVar::ZERO`] included.
    pub const fn vars_count(&self) -> usize {
        self.vars_count
    }

    /// The assigned wires and their values, in index order.
    pub fn public_vars(&self) -> &[(FieldVar, T)] {
        &self.public_values
    }

    /// The queries to prove, in the order they were made.
    pub fn queries(&self) -> &[QueryAnswerPair<FieldVar, WIDTH>] {
        &self.queries
    }

    /// The linear equations to prove.
    pub fn equations(&self) -> &[LinearEquation<T>] {
        &self.equations
    }

    /// The value assigned to `var`, if it is public.
    pub fn value(&self, var: FieldVar) -> Option<&T> {
        let index = self
            .public_values
            .binary_search_by_key(&var.index(), |(var, _)| var.index())
            .ok()?;
        self.public_values.get(index).map(|(_, value)| value)
    }

    /// Whether `witness` satisfies this instance under `permutation`.
    ///
    /// The trace must have one step per query, each step must be an
    /// evaluation of `permutation`, every wire must carry one value wherever
    /// it appears, public wires must carry their assigned value, and every
    /// equation must hold on those values.
    ///
    /// This is a plain comparison, not a constant-time one: it is meant for
    /// the prover checking its own witness, and for tests.
    pub fn is_witness_valid<P>(
        &self,
        permutation: &P,
        witness: &PermutationWitness<T, WIDTH>,
    ) -> bool
    where
        T: Ring,
        P: Permutation<WIDTH, U = T>,
    {
        if witness.trace.len() != self.queries.len() {
            return false;
        }

        let mut values: Vec<Option<T>> = alloc::vec![None; self.vars_count];
        for (var, value) in &self.public_values {
            match values.get_mut(var.index()) {
                Some(slot) => *slot = Some(value.clone()),
                None => return false,
            }
        }

        for (query, step) in self.queries.iter().zip(&witness.trace) {
            if permutation.permute(&step.input) != step.output {
                return false;
            }
            let wires = query.input.iter().chain(&query.output);
            let seen = step.input.iter().chain(&step.output);
            for (var, value) in wires.zip(seen) {
                match values.get_mut(var.index()) {
                    Some(Some(known)) if known == value => {}
                    Some(slot @ None) => *slot = Some(value.clone()),
                    _ => return false,
                }
            }
        }

        self.equations.iter().all(|equation| {
            let mut sum = T::ZERO;
            for term in equation.terms.terms() {
                let Some(Some(value)) = values.get(term.var.index()) else {
                    return false;
                };
                sum = Ring::add(sum, Ring::mul(term.weight.clone(), value.clone()));
            }
            sum == equation.image
        })
    }
}

/// A [`Permutation`] that records the values flowing through `permutation`.
///
/// Drive it through the same code as the [`PermutationRelation`], and the
/// trace it records is the [`PermutationWitness`] for the instance the
/// relation compiles to. Handles are reference counted like the relation's.
pub struct PermutationWitnessBuilder<P: Permutation<WIDTH>, const WIDTH: usize> {
    permutation: P,
    trace: Arc<RwLock<Vec<QueryAnswerPair<P::U, WIDTH>>>>,
}

impl<P: Permutation<WIDTH>, const WIDTH: usize> Clone for PermutationWitnessBuilder<P, WIDTH> {
    fn clone(&self) -> Self {
        Self {
            permutation: self.permutation.clone(),
            trace: Arc::clone(&self.trace),
        }
    }
}

impl<P: Permutation<WIDTH>, const WIDTH: usize> From<P> for PermutationWitnessBuilder<P, WIDTH> {
    fn from(permutation: P) -> Self {
        Self::new(permutation)
    }
}

impl<P: Permutation<WIDTH>, const WIDTH: usize> PermutationWitnessBuilder<P, WIDTH> {
    pub fn new(permutation: P) -> Self {
        Self {
            permutation,
            trace: Arc::default(),
        }
    }

    /// The permutation being traced.
    pub const fn permutation(&self) -> &P {
        &self.permutation
    }

    /// Evaluates the permutation on `input` and records the step.
    pub fn allocate_permutation(&self, input: &[P::U; WIDTH]) -> [P::U; WIDTH] {
        let output = self.permutation.permute(input);
        self.add_permutation(input, &output);
        output
    }

    /// Records a step without evaluating the permutation.
    pub fn add_permutation(&self, input: &[P::U; WIDTH], output: &[P::U; WIDTH]) {
        self.trace
            .write()
            .push(QueryAnswerPair::new(input.clone(), output.clone()));
    }

    /// The steps recorded so far.
    pub fn trace(&self) -> Vec<QueryAnswerPair<P::U, WIDTH>> {
        self.trace.read().clone()
    }

    /// The witness recorded so far.
    pub fn snapshot(&self) -> PermutationWitness<P::U, WIDTH> {
        PermutationWitness {
            trace: self.trace(),
        }
    }
}

impl<P: Permutation<WIDTH>, const WIDTH: usize> Permutation<WIDTH>
    for PermutationWitnessBuilder<P, WIDTH>
{
    type U = P::U;

    /// See the note on [`PermutationRelation`]'s implementation.
    fn permute_mut(&self, state: &mut [Self::U; WIDTH]) {
        *state = self.allocate_permutation(state);
    }

    fn permute(&self, state: &[Self::U; WIDTH]) -> [Self::U; WIDTH] {
        self.allocate_permutation(state)
    }
}

/// The trace of a permutation: the witness for a [`PermutationInstance`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermutationWitness<T, const WIDTH: usize> {
    pub(crate) trace: Vec<QueryAnswerPair<T, WIDTH>>,
}

impl<T, const WIDTH: usize> PermutationWitness<T, WIDTH> {
    /// One step per query, in the order the queries were made.
    pub fn trace(&self) -> &[QueryAnswerPair<T, WIDTH>] {
        &self.trace
    }
}
