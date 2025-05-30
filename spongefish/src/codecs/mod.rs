//!  Bindings to some popular libraries using zero-knowledge.

/// Extension traits macros, for both arkworks and group.
#[cfg(any(feature = "arkworks-algebra", feature = "zkcrypto-group"))]
mod traits;

pub mod arkworks;
mod bytes;
mod zerocopy;

pub use self::{
    bytes::{BytesPattern, BytesProver, BytesVerifier},
    zerocopy::{
        ZeroCopyHintPattern, ZeroCopyHintProver, ZeroCopyHintVerifier, ZeroCopyPattern,
        ZeroCopyProver, ZeroCopyVerifier,
    },
};

//#[cfg(feature = "arkworks-algebra")]
/// Arkworks's [algebra](https://github.com/arkworks-rs/algebra) bindings.
// pub mod arkworks_algebra;

#[cfg(feature = "zkcrypto-group")]
/// (In-progress) [group](https://github.com/zkcrypto/group) bindings.
/// This plugin is experimental and has not yet been thoroughly tested.
pub mod zkcrypto_group;

#[cfg(feature = "ark-serialize")]
/// Use [`ark_serialize`] to convert types to/from bytes.
pub mod zerocopy;

// #[cfg(feature = "serde-postcard")]
// /// Use [`zerocopy`] to convert types to/from bytes.
// pub mod zerocopy;

/// Unit-tests for inter-operability among libraries.
#[cfg(all(test, feature = "arkworks-algebra", feature = "zkcrypto-group"))]
mod tests;
