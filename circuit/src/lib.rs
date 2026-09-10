#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;
pub mod allocator;
#[cfg(feature = "p3-baby-bear")]
pub mod baby_bear;
pub mod permutation;
