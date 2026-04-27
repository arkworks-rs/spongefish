//! Defines the allocator and wires to be used for computing the key-derivation steps.

use alloc::{sync::Arc, vec::Vec};
use core::borrow::Borrow;

use hashbrown::HashMap;
use itertools::Itertools;
use spin::RwLock;
use spongefish::Unit;

/// A symbolic wire over which we perform out computation.
#[derive(Clone, Copy, Default, Hash, PartialEq, Eq)]
pub struct FieldVar(usize);

impl FieldVar {
    /// Maximum number of variables supported by the circuit allocator.
    pub const MAX_COUNT: usize = 1 << 30;
    /// The distinguished zero variable.
    pub const ZERO: Self = Self(0);

    /// Return the variable index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }

    /// Construct a variable from an index when it is within the supported range.
    #[must_use]
    pub const fn try_from_index(index: usize) -> Option<Self> {
        if index < Self::MAX_COUNT {
            Some(Self(index))
        } else {
            None
        }
    }
}

impl Unit for FieldVar {
    const ZERO: Self = Self::ZERO;
}

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
    public_values: HashMap<FieldVar, T>,
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
        let mut public_values = HashMap::new();
        public_values.insert(zero_var, T::ZERO);
        Self {
            state: Arc::new(RwLock::new(AllocatorState {
                vars_count: 1,
                public_values,
            })),
        }
    }

    #[must_use]
    pub fn new_field_var(&self) -> FieldVar {
        let mut state = self.state.write();
        assert!(
            state.vars_count < FieldVar::MAX_COUNT,
            "variable count exceeds supported maximum {}",
            FieldVar::MAX_COUNT,
        );
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
        {
            let state = self.state.read();
            let new_count = state
                .vars_count
                .checked_add(count)
                .expect("variable count overflow");
            assert!(
                new_count <= FieldVar::MAX_COUNT,
                "variable count exceeds supported maximum {}",
                FieldVar::MAX_COUNT,
            );
        }
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

    #[must_use]
    pub fn is_allocated(&self, var: FieldVar) -> bool {
        var.index() < self.vars_count()
    }

    /// Assigns the wire variable `var` to `val`.
    ///
    /// If the wire was already present, it is over-written.
    pub fn set_public_var(&self, var: FieldVar, val: T) {
        self.state.write().public_values.insert(var, val);
    }

    /// Sets a list of public variables.
    ///
    /// Takes as input two iterators (for wires and values respectively),
    /// and sets each of them to public values.
    ///
    /// # Panics
    ///
    /// If the iterators have different length, this function will panic.
    pub fn set_public_vars<Val, Var>(
        &self,
        vars: impl IntoIterator<Item = Var>,
        vals: impl IntoIterator<Item = Val>,
    ) where
        Var: Borrow<FieldVar>,
        Val: Borrow<T>,
    {
        self.state.write().public_values.extend(
            vars.into_iter()
                .zip_eq(vals)
                .map(|(var, val)| (*var.borrow(), val.borrow().clone())),
        );
    }

    #[must_use]
    pub fn public_vars(&self) -> Vec<(FieldVar, T)> {
        let mut public_values = self
            .state
            .read()
            .public_values
            .iter()
            .map(|(var, val)| (*var, val.clone()))
            .collect::<Vec<_>>();
        public_values.sort_unstable_by_key(|(var, _)| var.index());
        public_values
    }
}
