/// Multiple instantiations of the duplex sponge interface.
///
/// # Default instances.
///
/// 1. [`OWKeccakF1600`], the duplex sponge construction [[CO25], Section 3.3] for the
/// [`keccak::f1600`] permutation [Keccak-f].
/// Available with the `keccak` feature flag;
/// 2. [`OWAscon`], the duplex sponge construction [[CO25], Section 3.3] for the
/// [`ascon`] permutation [Ascon], used in overwrite mode.
/// Available with the `ascon` feature flag;
/// 3. [`Shake128`], based on the extensible output function [sha3::Shake128].
/// Available with the `sha3` feature flag (enabled by default);
/// 4. [`Blake3`], based on the extensible output function [blake3::Hasher].
/// Available with the `sha3` feature flag (enabled by default);
/// 5. [`SHA256`][self::SHA256], based on [sha2::Sha256] used as a stateful hash object.
/// Available with the `sha2` feature flag;
/// 6. [`SHA512`], based on [sha2::Sha512] used as a stateful hash object.
/// Available with the `sha2` feature flag.
///
/// # Security considerations
///
/// Only Constructions (1) and (2) are proven secure.
/// All other constructions are built using heuristics.
///
/// # Implementing your own hash
///
/// The duplex sponge construction [`DuplexSponge`] is described
/// in [[CO25], Section 3.3].
///
/// The extensible output function [`XOF`] wraps an object implementing [`digest::ExtendableOutput`]
/// and implements the duplex sponge interface with little-to-no code.
/// Its implementation has little differences with [`DuplexSponge`].
///
/// The hash bridge [`Hash`][crate::instantiations::Hash] wraps an object implementing
/// the [`digest::Digest`] trait, and implements the [`DuplexSpongeInterface`][crate::DuplexSpongeInterface]
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

#[cfg(feature = "keccak")]
/// A [`DuplexSponge`] instantiated with [`keccak::f1600`].
///
/// **Warning**: This function is not SHA-3.
/// Despite internally we use the same permutation function,
/// we build a duplex sponge in overwrite mode
/// on the top of it using the `DuplexSponge` trait.
pub type OWKeccakF1600 = DuplexSponge<permutations::KeccakF1600, 200, 136>;

#[cfg(feature = "ascon")]
/// A [`DuplexSponge`] instantiated with [`ascon`].
pub type OWAscon = DuplexSponge<permutations::Ascon12, 40, 16>;

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
#[cfg(test)]
#[allow(unused)]
fn _assert_duplex_sponge_impls() {
    fn assert_impl<T: crate::duplex_sponge::DuplexSpongeInterface>() {}

    #[cfg(feature = "sha3")]
    {
        assert_impl::<Shake128>();
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
