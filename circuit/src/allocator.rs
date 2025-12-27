//! Defines the allocator and wires to be used for computing the key-derivation steps.

use alloc::{sync::Arc, vec::Vec};

use spin::RwLock;
use spongefish::Unit;

/// A symbolic wire over which we perform out computation.
/// Wraps over a [`usize`]
#[derive(Clone, Copy, Default, Hash, PartialEq, Eq, Unit)]
pub struct FieldVar(pub usize);

impl core::fmt::Debug for FieldVar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "v({})", self.0)
    }
}

/// Allocator for field variables.
///
/// Creates a new wire identifier when requested,
/// and keeps tracks of the wires that have been declared as public.
#[derive(Clone)]
pub struct VarAllocator<T> {
    state: Arc<RwLock<AllocatorState<T>>>,
}

struct AllocatorState<T> {
    vars_count: usize,
    public_values: Vec<(FieldVar, T)>,
}

impl<T: Clone + Unit> Default for VarAllocator<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Unit> VarAllocator<T> {
    #[must_use]
    pub fn new() -> Self {
        let zero_var = FieldVar::ZERO;
        Self {
            state: Arc::new(RwLock::new(AllocatorState {
                vars_count: 1,
                public_values: Vec::from([(zero_var, T::ZERO)]),
            })),
        }
    }

    #[must_use]
    pub fn new_field_var(&self) -> FieldVar {
        let mut state = self.state.write();
        let var = FieldVar(state.vars_count);
        state.vars_count += 1;
        var
    }

    #[must_use]
    pub fn allocate_vars<const N: usize>(&self) -> [FieldVar; N] {
        let mut buf = [FieldVar::default(); N];
        for x in &mut buf {
            *x = self.new_field_var();
        }
        buf
    }

    #[must_use]
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

    #[must_use]
    pub fn vars_count(&self) -> usize {
        self.state.read().vars_count
    }

    pub fn set_public_var(&self, val: FieldVar, var: T) {
        self.state.write().public_values.push((val, var));
    }

    pub fn set_public_vars<Val, Var>(
        &self,
        vars: impl IntoIterator<Item = Var>,
        vals: impl IntoIterator<Item = Val>,
    ) where
        Var: core::borrow::Borrow<FieldVar>,
        Val: core::borrow::Borrow<T>,
    {
        self.state.write().public_values.extend(
            vars.into_iter()
                .zip(vals)
                .map(|(var, val)| (*var.borrow(), val.borrow().clone())),
        );
    }

    #[must_use]
    pub fn public_vars(&self) -> Vec<(FieldVar, T)> {
        self.state.read().public_values.clone()
    }
}
