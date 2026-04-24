//! DSFS compiler: Duplex-Sponge Fiat-Shamir transformation.
//!
//! This module implements the DSFS transformation of Chiesa-Orru 2025,
//! Construction 4.3, for `ia-core` public-coin interactive protocols.
//!
//! The split of responsibilities is:
//!
//! - `ia-core` defines the abstract protocol vocabulary: channel traits,
//!   interactive arguments/reductions, `NargProof`, and the
//!   `NonInteractiveArgument` / `NonInteractiveReduction` traits.
//! - `spongefish::dsfs` owns the concrete transformation from those interactive
//!   protocols into non-interactive proofs using spongefish transcripts.
//! - Protocol implementations should only call the channel API. They should not
//!   instantiate sponges, derive Fiat-Shamir challenges directly, or inspect
//!   transcript internals.
//!
//! The free functions are the byte-oriented convenience API:
//!
//! - [`prove`] / [`verify`] compile an `InteractiveArgument`.
//! - [`prove_reduction`] / [`verify_reduction`] compile an `InteractiveReduction`.
//! - `*_with_salt` variants add an explicit prover-chosen salt message before
//!   protocol execution.
//! - `*_with_sponge` variants allow selecting a byte-oriented sponge such as
//!   [`Keccak`] or [`StdHash`].
//!
//! Prover functions return [`ia_core::NargProof`]. Its `as_bytes()` method
//! exposes the raw DSFS proof string expected by the verifier functions.
//! Verification always checks EOF, so trailing proof bytes are rejected.
//!
//! The [`Dsfs`] and [`DsfsReduction`] wrappers implement the abstract
//! non-interactive traits from `ia-core` for callers that want to pass a DSFS
//! compiler around as a first-class NARG.
//!
//! Transcript invariants maintained here:
//!
//! - public inputs are absorbed before the first challenge;
//! - every prover message is absorbed before the next verifier challenge;
//! - verifier replay is deterministic;
//! - verification consumes exactly the expected proof bytes.

mod channel;
mod compile;
mod narg_security;
mod params;

pub use channel::TranscriptSponge;
pub use channel::{SpongeProver, SpongeVerifier};
pub use compile::{
    prove, prove_reduction, prove_reduction_with_salt, prove_reduction_with_sponge,
    prove_reduction_with_sponge_and_salt, prove_with_salt, prove_with_sponge,
    prove_with_sponge_and_salt, verify, verify_reduction, verify_reduction_with_salt,
    verify_reduction_with_sponge, verify_reduction_with_sponge_and_salt, verify_with_salt,
    verify_with_sponge, verify_with_sponge_and_salt, ByteDuplexSponge, Dsfs, DsfsReduction,
};
pub use narg_security::{reduction_security, security, NargSecurity};
pub use params::{
    DuplexSpongeParamsExt, Keccak, SpongeInfo, SpongeParams, StdHash, STD_HASH_SPONGE_PARAMS,
    STD_SPONGE_PARAMS,
};
