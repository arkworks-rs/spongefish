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
pub type Keccak = DuplexSponge<permutations::KeccakF1600, 200, 136>;

#[cfg(feature = "ascon")]
/// A [`DuplexSponge`] instantiated with [`ascon`].
pub type Ascon12 = DuplexSponge<permutations::Ascon12, 40, 16>;

#[cfg(feature = "sha3")]
/// SHAKE-128's XOF used as a [`DuplexSpongeInterface`][`crate::DuplexSpongeInterface`].
pub type Shake128 = xof::XOF<sha3::Shake128>;

/// KangarooTwelve (K12) - fast reduced-round Keccak variant
///
/// Note: K12 uses a static lifetime for the customization string
#[cfg(feature = "k12")]
pub type KangarooTwelve = xof::XOF<k12::KangarooTwelve<'static>>;

/// Blake3's XOF used as a [`DuplexSpongeInterface`][`crate::DuplexSpongeInterface`].
#[cfg(feature = "blake3")]
pub type Blake3 = xof::XOF<blake3::Hasher>;

/// SHA-256's [`Digest`][`digest::Digest`] used as a [`DuplexSpongeInterface`][`crate::DuplexSpongeInterface`]
#[cfg(feature = "sha2")]
pub type SHA256 = hash::Hash<sha2::Sha256>;
/// SHA-512's [`Digest`][`digest::Digest`] used as a [`DuplexSpongeInterface`][`crate::DuplexSpongeInterface`]
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
    assert_impl::<Keccak>();
    #[cfg(feature = "ascon")]
    assert_impl::<Ascon12>();
}
