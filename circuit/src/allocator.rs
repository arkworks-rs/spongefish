//! Wire variables and the allocator that mints them.

use alloc::{sync::Arc, vec::Vec};
use core::{borrow::Borrow, fmt};

use spin::RwLock;
use spongefish::Unit;

/// A wire of a relation: a plain index. Index `0` is [`FieldVar::ZERO`], the
/// wire every relation assigns the value zero.
#[derive(Clone, Copy, Default, Hash, PartialEq, Eq)]
pub struct FieldVar(usize);

impl FieldVar {
    /// Maximum number of variables a relation can allocate.
    pub const MAX_COUNT: usize = 1 << 30;
    /// The distinguished zero wire, allocated and assigned by every relation.
    pub const ZERO: Self = Self(0);

    /// The variable index.
    pub const fn index(self) -> usize {
        self.0
    }

    /// A variable from an index within the supported range.
    pub const fn try_from_index(index: usize) -> Option<Self> {
        if index < Self::MAX_COUNT {
            Some(Self(index))
        } else {
            None
        }
    }
}

impl fmt::Debug for FieldVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v({})", self.0)
    }
}

impl Unit for FieldVar {
    const ZERO: Self = Self::ZERO;
}

/// Allocator for wire variables.
///
/// Mints a fresh wire on request and records the values of the wires that
/// have been assigned, which are the relation's public inputs. Handles are
/// reference counted, so relations of different widths can share one
/// namespace through [`PermutationRelation::with_allocator`].
///
/// [`PermutationRelation::with_allocator`]: crate::PermutationRelation::with_allocator
pub struct VarAllocator<T> {
    /// One slot per allocated wire, `Some` once assigned.
    values: Arc<RwLock<Vec<Option<T>>>>,
}

impl<T> Clone for VarAllocator<T> {
    fn clone(&self) -> Self {
        Self {
            values: Arc::clone(&self.values),
        }
    }
}

impl<T: Unit> Default for VarAllocator<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Unit> VarAllocator<T> {
    /// An allocator holding only [`FieldVar::ZERO`], assigned to `T::ZERO`.
    pub fn new() -> Self {
        Self {
            values: Arc::new(RwLock::new(alloc::vec![Some(T::ZERO)])),
        }
    }

    /// Allocate one wire, unassigned.
    ///
    /// # Panics
    ///
    /// Panics when [`FieldVar::MAX_COUNT`] wires have already been allocated.
    pub fn allocate_var(&self) -> FieldVar {
        let mut values = self.values.write();
        assert!(
            values.len() < FieldVar::MAX_COUNT,
            "variable count exceeds supported maximum {}",
            FieldVar::MAX_COUNT,
        );
        values.push(None);
        FieldVar(values.len() - 1)
    }

    /// Allocate `N` wires, so `let [x, y] = allocator.allocate_vars()`
    /// allocates two at once.
    pub fn allocate_vars<const N: usize>(&self) -> [FieldVar; N] {
        core::array::from_fn(|_| self.allocate_var())
    }

    /// Allocate `count` wires.
    ///
    /// # Panics
    ///
    /// Panics, before allocating anything, if the total would exceed
    /// [`FieldVar::MAX_COUNT`].
    pub fn allocate_vars_vec(&self, count: usize) -> Vec<FieldVar> {
        {
            let values = self.values.read();
            let total = values
                .len()
                .checked_add(count)
                .expect("variable count overflow");
            assert!(
                total <= FieldVar::MAX_COUNT,
                "variable count exceeds supported maximum {}",
                FieldVar::MAX_COUNT,
            );
        }
        (0..count).map(|_| self.allocate_var()).collect()
    }

    /// Allocate one wire and assign it `value`.
    pub fn allocate_var_with(&self, value: T) -> FieldVar
    where
        T: PartialEq,
    {
        let var = self.allocate_var();
        self.set_var(var, value);
        var
    }

    /// Allocate `N` wires and assign them `values`.
    pub fn allocate_vars_with<const N: usize>(&self, values: &[T; N]) -> [FieldVar; N]
    where
        T: PartialEq,
    {
        let vars = self.allocate_vars();
        self.set_vars(vars, values);
        vars
    }

    /// Allocate one wire per element of `values` and assign them.
    pub fn allocate_vars_vec_with(&self, values: &[T]) -> Vec<FieldVar>
    where
        T: PartialEq,
    {
        let vars = self.allocate_vars_vec(values.len());
        self.set_vars(vars.iter().copied(), values);
        vars
    }

    /// The number of wires allocated so far, [`FieldVar::ZERO`] included.
    pub fn vars_count(&self) -> usize {
        self.values.read().len()
    }

    /// Whether `var` was allocated by this allocator.
    pub fn is_allocated(&self, var: FieldVar) -> bool {
        var.index() < self.vars_count()
    }

    /// Assign `value` to `var`, making the wire public.
    ///
    /// # Panics
    ///
    /// Panics if `var` was not allocated by this allocator, or if it already
    /// holds a different value.
    pub fn set_var(&self, var: FieldVar, value: T)
    where
        T: PartialEq,
    {
        let mut values = self.values.write();
        let slot = values
            .get_mut(var.index())
            .unwrap_or_else(|| panic!("unallocated variable {}", var.index()));
        match slot {
            Some(assigned) => assert!(
                *assigned == value,
                "conflicting assignment for variable {}",
                var.index()
            ),
            None => *slot = Some(value),
        }
    }

    /// Assign each wire of `vars` the corresponding element of `values`.
    ///
    /// # Panics
    ///
    /// Panics if the two iterators differ in length, or as [`Self::set_var`]
    /// does for any pair.
    pub fn set_vars<Var, Val>(
        &self,
        vars: impl IntoIterator<Item = Var>,
        values: impl IntoIterator<Item = Val>,
    ) where
        Var: Borrow<FieldVar>,
        Val: Borrow<T>,
        T: PartialEq,
    {
        let mut vars = vars.into_iter();
        let mut values = values.into_iter();
        loop {
            match (vars.next(), values.next()) {
                (Some(var), Some(value)) => self.set_var(*var.borrow(), value.borrow().clone()),
                (None, None) => return,
                _ => panic!("set_vars: variables and values differ in length"),
            }
        }
    }

    /// The value of `var`, if it has been assigned.
    pub fn value(&self, var: FieldVar) -> Option<T> {
        self.values.read().get(var.index()).cloned().flatten()
    }

    /// The assigned wires and their values, in index order.
    pub fn public_vars(&self) -> Vec<(FieldVar, T)> {
        self.values
            .read()
            .iter()
            .enumerate()
            .filter_map(|(index, value)| Some((FieldVar(index), value.clone()?)))
            .collect()
    }

    /// A snapshot of every slot, assigned or not.
    pub(crate) fn values(&self) -> Vec<Option<T>> {
        self.values.read().clone()
    }
}
