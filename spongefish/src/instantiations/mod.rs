//! Concrete hash backends:
//!
//! - the [`Hash`][crate::instantiations::Hash] bridge for fixed-output digests,
//! - the [`XOF`][crate::instantiations::XOF] bridge for extendable-output functions,
//! - the raw permutations behind the [`DuplexSponge`][crate::duplex_sponge::DuplexSponge] construction,
//!
//! along with the named suites built from them.

mod digest;
mod permutations;
mod suites;
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
pub use xof::{XofRate, XOF};

pub use self::digest::Hash;
