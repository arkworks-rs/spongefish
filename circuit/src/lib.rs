#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;
pub mod allocator;
#[cfg(feature = "p3-baby-bear")]
pub mod baby_bear;
pub mod encoding;
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

// The README's examples are compiled here rather than in `spongefish`: this
// crate reaches everything they use, `spongefish` with `derive`, BabyBear,
// the builders, and `spongefish-pow` as a dev-dependency. They are not
// repeated in the rendered documentation.
#[cfg(all(doctest, feature = "p3-baby-bear"))]
#[doc = include_str!("../../README.md")]
pub mod readme_doctests {}
