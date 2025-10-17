#![no_std]

//! Re-export of arkworks algebra codecs from spongefish core.
//!
//! This crate exists for backwards compatibility. New code should use
//! `spongefish::backend::arkworks` directly.

pub use spongefish::backend::arkworks::*;
