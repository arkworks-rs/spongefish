/// Hash function support (e.g. [`sha2`](https://crates.io/crates/sha2).
pub mod hash;

pub mod permutations;
pub mod xof;

pub use hash::Hash;
pub use xof::XOF;

pub use super::duplex_sponge::DuplexSponge;

// SHA-3 family (Shake128, TurboShake128)
#[cfg(feature = "sha3")]
pub type Shake128 = xof::XOF<sha3::Shake128>;

// Blake3
#[cfg(feature = "blake3")]
pub type Blake3 = hash::Hash<blake3::Hasher>;

// SHA-2 family (SHA256, SHA512)
#[cfg(feature = "sha2")]
pub type SHA256 = hash::Hash<sha2::Sha256>;
#[cfg(feature = "sha2")]
pub type SHA512 = hash::Hash<sha2::Sha512>;

// Blake2 family
#[cfg(feature = "blake2")]
pub type Blake2b512 = hash::Hash<blake2::Blake2b512>;
#[cfg(feature = "blake2")]
pub type Blake2s256 = hash::Hash<blake2::Blake2s256>;

// Keccak-based duplex sponge
#[cfg(feature = "keccak")]
/// A [`DuplexSponge`] instantiated with [`keccak::f1600`].
///
/// **Warning**: This function is not SHA3.
/// Despite internally we use the same permutation function,
/// we build a duplex sponge in overwrite mode
/// on the top of it using the `DuplexSponge` trait.
pub type OWKeccakF1600 = DuplexSponge<permutations::KeccakF1600>;

// Ascon
#[cfg(feature = "ascon")]
/// A [`DuplexSponge`] instantiated with [`ascon`].
pub type OWAscon = DuplexSponge<permutations::Ascon12>;
