//! Defines the allocator and wires to be used for computing the key-derivation steps.

use alloc::{rc::Rc, vec::Vec};
use core::{cell::RefCell, usize};

use spongefish::Unit;

/// A symbolic wire over which we perform out computation.
/// Wraps over a [`usize`]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Unit)]
pub struct FieldVar(pub usize);

// /// A witness-instance pair that builds at the same time the instance and the relation.
// ///
// /// # Semantics
// ///
// /// When we deref this object, we are talking about its value.
// /// When we get the ref of this object, we are talking about its symbolic value.
// #[derive(Clone, Debug, Unit)]
// pub struct WitnessInstancePair<T: Unit>(FieldVar, T);

/// Allocator for field variables.
///
/// Creates a new wire identifier when requested,
/// and keeps tracks of the wires that have been declared as public.
#[derive(Clone)]
pub struct VarAllocator<T> {
    state: Rc<RefCell<AllocatorState<T>>>,
}

struct AllocatorState<T> {
    vars_count: usize,
    public_values: Vec<(FieldVar, T)>,
}

impl<T: Clone> VarAllocator<T> {
    pub fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(AllocatorState {
                vars_count: 0,
                public_values: Vec::new(),
            })),
        }
    }

    pub fn new_field_var(&self) -> FieldVar {
        let mut state = self.state.borrow_mut();
        let var = FieldVar(state.vars_count);
        state.vars_count += 1;
        var
    }

    pub fn allocate_vars<const N: usize>(&self) -> [FieldVar; N] {
        let mut buf = [FieldVar::default(); N];
        buf.iter_mut().for_each(|x| *x = self.new_field_var());
        buf
    }

    pub fn allocate_vars_vec(&self, count: usize) -> Vec<FieldVar> {
        (0..count).map(|_| self.new_field_var()).collect()
    }

    pub fn allocate_public<const N: usize>(&self, public_values: &[T; N]) -> [FieldVar; N] {
        let vars = self.allocate_vars();
        self.set_public_vars(vars, public_values);
        vars
    }

    pub fn allocate_public_vec(&self, public_values: &[T]) -> Vec<FieldVar> {
        let vars = self.allocate_vars_vec(public_values.len());
        self.set_public_vars(vars.clone(), public_values);
        vars
    }

    pub fn vars_count(&self) -> usize {
        self.state.borrow().vars_count
    }

    pub fn set_public_var(&self, val: FieldVar, var: T) {
        self.state.borrow_mut().public_values.push((val, var));
    }

    pub fn set_public_vars<Val, Var>(
        &self,
        vars: impl IntoIterator<Item = Var>,
        vals: impl IntoIterator<Item = Val>,
    ) where
        Var: core::borrow::Borrow<FieldVar>,
        Val: core::borrow::Borrow<T>,
    {
        self.state.borrow_mut().public_values.extend(
            vars.into_iter()
                .zip(vals)
                .map(|(var, val)| (*var.borrow(), val.borrow().clone())),
        )
    }

    pub fn public_vars(&self) -> Vec<(usize, T)> {
        self.state
            .borrow()
            .public_values
            .iter()
            .map(|(var, val)| (var.0, val.clone()))
            .collect()
    }
}
