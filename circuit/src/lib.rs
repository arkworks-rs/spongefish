#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;
pub mod allocator;
#[cfg(feature = "p3-baby-bear")]
pub mod baby_bear;
mod error;
pub mod expr;
pub mod permutation;

pub use allocator::{FieldVar, VarAllocator};
pub use error::InvalidRelation;
pub use expr::{Ring, Sum, Weighted};
pub use permutation::{
    LinearEquation, PermutationInstance, PermutationRelation, PermutationWitness,
    PermutationWitnessBuilder, QueryAnswerPair,
};
