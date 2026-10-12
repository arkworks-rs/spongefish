//! Concrete hash backends:
//!
//! - the `Hash` bridge for fixed-output digests (requires `digest`),
//! - the `XOF` bridge for extendable-output functions (requires `digest`),
//! - the raw permutations behind the [`DuplexSponge`](crate::DuplexSponge) construction,
//!
//! along with the named suites built from them.

#[cfg(feature = "digest")]
mod digest;
mod permutations;
mod suites;
#[cfg(feature = "digest")]
mod xof;

#[cfg(feature = "ascon")]
pub use permutations::AsconP12;
#[cfg(feature = "keccak")]
pub use permutations::KeccakF1600;
#[cfg(feature = "ascon")]
pub use suites::Ascon12;
#[cfg(feature = "keccak")]
pub use suites::Keccak;
#[cfg(feature = "turboshake128")]
pub use suites::{Shake128, TurboShake128};
#[cfg(feature = "digest")]
pub use xof::{XofRate, XOF};

#[cfg(feature = "digest")]
pub use self::digest::Hash;
