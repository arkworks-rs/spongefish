//! Linear expressions over wires: `x * a + y * b + z`.

use alloc::vec::Vec;
use core::ops::{Add, Mul};

use spongefish::Unit;

use crate::allocator::FieldVar;

/// The arithmetic a value type needs to appear in a linear equation.
///
/// [`Unit`] supplies zero and cloning; this adds one, addition, and
/// multiplication, which is what evaluating `Σ weight_i · value_i` and giving
/// a bare wire the weight one require.
///
/// The integer units form the Boolean ring: addition is XOR, multiplication
/// is AND, and one is all ones. A weight is then a bit mask and an equation
/// is an XOR relation between masked wires, which is what a statement about
/// a byte-oriented permutation needs. A field unit uses its field arithmetic.
#[allow(clippy::return_self_not_must_use)]
pub trait Ring: Unit + PartialEq {
    /// The multiplicative identity.
    const ONE: Self;

    fn add(self, other: Self) -> Self;

    fn mul(self, other: Self) -> Self;
}

macro_rules! impl_boolean_ring {
    ($($t:ty),*) => {$(
        impl Ring for $t {
            const ONE: Self = !0;

            fn add(self, other: Self) -> Self {
                self ^ other
            }

            fn mul(self, other: Self) -> Self {
                self & other
            }
        }
    )*};
}

impl_boolean_ring!(u8, u32, u64, u128);

/// A wire scaled by a constant: `weight · var`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Weighted<T> {
    pub var: FieldVar,
    pub weight: T,
}

/// A linear combination of wires, the left-hand side of a
/// [`LinearEquation`][crate::permutation::LinearEquation].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sum<T>(Vec<Weighted<T>>);

impl<T> Sum<T> {
    /// The terms of the sum, in the order they were added.
    pub fn terms(&self) -> &[Weighted<T>] {
        &self.0
    }
}

impl<T> Default for Sum<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> From<Weighted<T>> for Sum<T> {
    fn from(term: Weighted<T>) -> Self {
        Self(alloc::vec![term])
    }
}

/// A bare wire is the term `1 · var`.
impl<T: Ring> From<FieldVar> for Weighted<T> {
    fn from(var: FieldVar) -> Self {
        Self {
            var,
            weight: T::ONE,
        }
    }
}

impl<T: Ring> From<FieldVar> for Sum<T> {
    fn from(var: FieldVar) -> Self {
        Weighted::from(var).into()
    }
}

impl<T, U: Into<Weighted<T>>> FromIterator<U> for Sum<T> {
    fn from_iter<I: IntoIterator<Item = U>>(iter: I) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

impl<T, U: Into<Self>> core::iter::Sum<U> for Sum<T> {
    fn sum<I: IntoIterator<Item = U>>(iter: I) -> Self {
        iter.into_iter().fold(Self::default(), |acc, rhs| acc + rhs)
    }
}

impl<T> Mul<T> for FieldVar {
    type Output = Weighted<T>;

    fn mul(self, weight: T) -> Weighted<T> {
        Weighted { var: self, weight }
    }
}

impl<T: Ring> Mul<T> for Weighted<T> {
    type Output = Self;

    fn mul(self, rhs: T) -> Self {
        Self {
            var: self.var,
            weight: Ring::mul(self.weight, rhs),
        }
    }
}

impl<T, Rhs: Into<Self>> Add<Rhs> for Sum<T> {
    type Output = Self;

    fn add(mut self, rhs: Rhs) -> Self {
        self.0.extend(rhs.into().0);
        self
    }
}

impl<T, Rhs: Into<Sum<T>>> Add<Rhs> for Weighted<T> {
    type Output = Sum<T>;

    fn add(self, rhs: Rhs) -> Sum<T> {
        Sum::from(self) + rhs
    }
}

// A wire on the left of `+` needs the right-hand side to name `T`, so
// `a + b * w` and `a + sum` work while `a + b` alone does not: give one
// term a weight, or collect the wires with `Sum::from_iter`.
impl<T: Ring> Add<Weighted<T>> for FieldVar {
    type Output = Sum<T>;

    fn add(self, rhs: Weighted<T>) -> Sum<T> {
        Sum::from(self) + rhs
    }
}

impl<T: Ring> Add<Sum<T>> for FieldVar {
    type Output = Sum<T>;

    fn add(self, rhs: Sum<T>) -> Sum<T> {
        Sum::from(self) + rhs
    }
}
