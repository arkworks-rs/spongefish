/// Hash function support (e.g. [`sha2`](https://crates.io/crates/sha2).
pub mod hash;

pub mod permutations;
pub mod xof;

pub use hash::Hash;
pub use xof::XOF;

pub use super::duplex_sponge::DuplexSponge;

pub type Shake128 = xof::XOF<sha3::Shake128>;
pub type Blake3 = xof::XOF<blake3::Hasher>;
pub type SHA256 = hash::Hash<sha2::Sha256>;
pub type SHA512 = hash::Hash<sha2::Sha512>;
pub type Blake2b512 = hash::Hash<blake2::Blake2b512>;
pub type TurboShake128 = xof::XOF<sha3::TurboShake128>;

/// A duplex sponge based on the permutation [`keccak::f1600`]
/// using [`DuplexSponge`].
///
/// **Warning**: This function is not SHA3.
/// Despite internally we use the same permutation function,
/// we build a duplex sponge in overwrite mode
/// on the top of it using the `DuplexSponge` trait.
type OWKeccakF1600 = DuplexSponge<permutations::KeccakF1600>;

type OWAscon = DuplexSponge<permutations::Ascon12>;
