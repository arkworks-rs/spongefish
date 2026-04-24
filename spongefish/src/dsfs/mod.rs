//! DSFS compiler: Duplex-Sponge Fiat-Shamir transformation (Construction 4.3, Chiesa-Orru 2025).
//!
//! Wraps spongefish's `ProverState` and `VerifierState` behind ia-core's
//! abstract channel traits. This is the **only** layer that touches the sponge.
//!
//! Supports both interactive arguments (`prove`/`verify`) and interactive
//! oracle reductions (`prove_reduction`/`verify_reduction`).
//!
//! Submodules: [`params`], [`narg_security`], [`channel`], [`compile`].

mod channel;
mod compile;
mod narg_security;
mod params;

pub use channel::{SpongeProver, SpongeVerifier};
pub use channel::TranscriptSponge;
pub use compile::{
    ByteDuplexSponge, Dsfs, DsfsReduction, prove, prove_reduction, prove_reduction_with_salt,
    prove_reduction_with_sponge, prove_reduction_with_sponge_and_salt, prove_with_salt,
    prove_with_sponge, prove_with_sponge_and_salt, verify, verify_reduction,
    verify_reduction_with_salt, verify_reduction_with_sponge,
    verify_reduction_with_sponge_and_salt, verify_with_salt, verify_with_sponge,
    verify_with_sponge_and_salt,
};
pub use narg_security::{NargSecurity, reduction_security, security};
pub use params::{
    DuplexSpongeParamsExt, Keccak, SpongeInfo, STD_HASH_SPONGE_PARAMS, STD_SPONGE_PARAMS,
    SpongeParams, StdHash,
};
