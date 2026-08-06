/// The duplex sponges of draft-irtf-cfrg-fiat-shamir (SHAKE128, TurboSHAKE128).
pub mod dsfs;
#[cfg(feature = "digest")]
pub mod hash;

pub mod permutations;
#[cfg(feature = "digest")]
pub mod xof;

#[cfg(feature = "digest")]
pub use hash::Hash;
#[cfg(feature = "digest")]
pub use xof::XOF;

pub use super::duplex_sponge::DuplexSponge;

/// The SHAKE128 duplex sponge of draft-irtf-cfrg-fiat-shamir.
///
/// This is the library's default hash ([`StdHash`][crate::StdHash]).
pub use dsfs::Shake128;
/// The TurboSHAKE128 duplex sponge of draft-irtf-cfrg-fiat-shamir.
pub use dsfs::TurboShake128;

#[cfg(feature = "keccak")]
/// A [`DuplexSponge`] instantiated with [`keccak::Keccak::with_f1600`].
///
/// **Warning**: This is **not** SHA-3 and **not** the SHAKE128 suite of
/// draft-irtf-cfrg-fiat-shamir (use [`Shake128`] for that — the two produce
/// different bytes for the same inputs). Despite using the same permutation,
/// this type is a duplex sponge in overwrite mode, the construction analyzed
/// in [CO25].
///
/// [CO25]: https://eprint.iacr.org/2025/536.pdf
pub type Keccak = DuplexSponge<permutations::KeccakF1600, 200, 136>;

#[cfg(feature = "ascon")]
/// A [`DuplexSponge`] instantiated with [`ascon`] (overwrite mode; not a
/// draft-irtf-cfrg-fiat-shamir suite).
pub type Ascon12 = DuplexSponge<permutations::Ascon12, 40, 16>;

/// Blake3's XOF used as a [`DuplexSpongeInterface`][`crate::DuplexSpongeInterface`]
/// (not a draft-irtf-cfrg-fiat-shamir suite).
///
/// On the `digest 0.11` stack, BLAKE3's `traits-preview` feature implements the
/// same XOF traits as SHAKE, so no dedicated wrapper is needed.
#[cfg(feature = "blake3")]
pub type Blake3 = xof::XOF<blake3::Hasher>;

/// SHA-256's [`Digest`][`digest::Digest`] used as a [`DuplexSpongeInterface`][`crate::DuplexSpongeInterface`]
/// (not a draft-irtf-cfrg-fiat-shamir suite).
#[cfg(feature = "sha2")]
pub type SHA256 = hash::Hash<sha2::Sha256>;
/// SHA-512's [`Digest`][`digest::Digest`] used as a [`DuplexSpongeInterface`][`crate::DuplexSpongeInterface`]
/// (not a draft-irtf-cfrg-fiat-shamir suite).
#[cfg(feature = "sha2")]
pub type SHA512 = hash::Hash<sha2::Sha512>;

// Blake2 family (not draft-irtf-cfrg-fiat-shamir suites).
#[cfg(feature = "blake2")]
pub type Blake2b512 = hash::Hash<blake2::Blake2b512>;
#[cfg(feature = "blake2")]
pub type Blake2s256 = hash::Hash<blake2::Blake2s256>;

// Make sure that all instantiations satisfy the DuplexSpongeInterface trait.
#[cfg(test)]
#[allow(unused)]
const fn _assert_duplex_sponge_impls() {
    const fn assert_impl<T: crate::duplex_sponge::DuplexSpongeInterface>() {}
    const fn assert_init_impl<T: crate::duplex_sponge::DuplexSpongeInit>() {}

    assert_impl::<Shake128>();
    assert_impl::<TurboShake128>();
    assert_init_impl::<Shake128>();
    assert_init_impl::<TurboShake128>();
    #[cfg(feature = "blake3")]
    assert_impl::<Blake3>();
    #[cfg(feature = "sha2")]
    {
        assert_impl::<SHA256>();
        assert_impl::<SHA512>();
        assert_init_impl::<SHA256>();
    }
    #[cfg(feature = "blake2")]
    {
        assert_impl::<Blake2b512>();
        assert_impl::<Blake2s256>();
    }
    #[cfg(feature = "keccak")]
    {
        assert_impl::<Keccak>();
        assert_init_impl::<Keccak>();
    }
    #[cfg(feature = "ascon")]
    assert_impl::<Ascon12>();
}
