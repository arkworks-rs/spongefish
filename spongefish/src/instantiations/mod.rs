/// Multiple instantiations of the duplex sponge interface.
///
/// This module contains:
///
/// - The [`DuplexSponge`] construction from [[CO25]] based on top of a permutation function.
///   Two instantiations are provided:
///
///   1. [`OWKeccakF1600`], based on the [Keccak-f] permutation and available with the `keccak` feature flag;
///   2. [`OWAscon`], based on the [Ascon] permutation and available with the `ascon` feature flag;
///
/// - A [`Hash`] interfacing the [`digest::Digest`] trait implementations with the [`DuplexSponge`] API.
///   This is instantiated for:
///
///   1. [`SHA256`], based on [SHA2] and available with the `sha2` feature flag;
///   2. [`SHA512`], based on [SHA2] and available with the `sha2` feature flag.
///
///
/// - A [`XOF`] interfacing the [`digest::ExtensibleOutput`]
///
/// [SHA2]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
/// [Keccak-f]: https://keccak.team/keccak_specs_summary.html
/// [Ascon]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.pdf
/// [CO25]: https://eprint.iacr.org/2025/536.pdf
pub mod hash;

pub mod permutations;
pub mod xof;

pub use hash::Hash;
pub use xof::XOF;

pub use super::duplex_sponge::DuplexSponge;
// Keccak-based duplex sponge
#[cfg(feature = "keccak")]
/// A [`DuplexSponge`] instantiated with [`keccak::f1600`].
///
/// **Warning**: This function is not SHA3.
/// Despite internally we use the same permutation function,
/// we build a duplex sponge in overwrite mode
/// on the top of it using the `DuplexSponge` trait.
pub type OWKeccakF1600 = DuplexSponge<permutations::KeccakF1600, 136>;

// Ascon
#[cfg(feature = "ascon")]
/// A [`DuplexSponge`] instantiated with [`ascon`].
pub type OWAscon = DuplexSponge<permutations::Ascon12, 16>;

// SHA-3 family
#[cfg(feature = "sha3")]
pub type Shake128 = xof::XOF<sha3::Shake128>;

// KangarooTwelve (K12) - fast reduced-round Keccak variant
// Note: K12 requires a static lifetime for the customization string
#[cfg(feature = "k12")]
pub type KangarooTwelve = xof::XOF<k12::KangarooTwelve<'static>>;

// Blake3
#[cfg(feature = "blake3")]
pub type Blake3 = xof::XOF<blake3::Hasher>;

// SHA-2 family
#[cfg(feature = "sha2")]
pub type SHA256 = hash::Hash<sha2::Sha256>;
#[cfg(feature = "sha2")]
pub type SHA512 = hash::Hash<sha2::Sha512>;

// Blake2 family
#[cfg(feature = "blake2")]
pub type Blake2b512 = hash::Hash<blake2::Blake2b512>;
#[cfg(feature = "blake2")]
pub type Blake2s256 = hash::Hash<blake2::Blake2s256>;

// Make sure that all instantiations satisfy the DuplexSpongeInterface trait.
#[allow(unused)]
fn _assert_duplex_sponge_impls() {
    fn assert_impl<T: crate::duplex_sponge::DuplexSpongeInterface>() {}

    #[cfg(feature = "sha3")]
    {
        assert_impl::<Shake128>();
        // assert_impl::<TurboShake128>();
    }
    #[cfg(feature = "k12")]
    assert_impl::<KangarooTwelve>();
    #[cfg(feature = "blake3")]
    assert_impl::<Blake3>();
    #[cfg(feature = "sha2")]
    {
        assert_impl::<SHA256>();
        assert_impl::<SHA512>();
    }
    #[cfg(feature = "blake2")]
    {
        assert_impl::<Blake2b512>();
        assert_impl::<Blake2s256>();
    }
    #[cfg(feature = "keccak")]
    assert_impl::<OWKeccakF1600>();
    #[cfg(feature = "ascon")]
    assert_impl::<OWAscon>();
}
