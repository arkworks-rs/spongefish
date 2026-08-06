//! The named duplex sponge instantiations.
//!
//! [`Shake128`] and [`TurboShake128`] are the suites of
//! draft-irtf-cfrg-fiat-shamir. [`Keccak`] and [`Ascon12`] are overwrite-mode
//! duplex sponges outside the draft.

#[cfg(any(feature = "keccak", feature = "ascon"))]
use super::permutations;
#[cfg(feature = "turboshake128")]
use super::xof::XOF;
#[cfg(any(feature = "keccak", feature = "ascon"))]
use crate::duplex_sponge::DuplexSponge;

/// The SHAKE128 duplex sponge of draft-irtf-cfrg-fiat-shamir.
#[cfg(feature = "turboshake128")]
pub type Shake128 = XOF<shake::Shake128>;

/// The TurboSHAKE128 duplex sponge of draft-irtf-cfrg-fiat-shamir
/// (`Keccak-p[1600, 12]`, RFC 9861, `D = 0x1F`).
///
/// This is the library's default hash ([`StdHash`][crate::StdHash]).
#[cfg(feature = "turboshake128")]
pub type TurboShake128 = XOF<::turboshake::TurboShake128>;

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
pub type Ascon12 = DuplexSponge<permutations::AsconP12, 40, 16>;

#[cfg(test)]
#[allow(unused)]
const fn _assert_duplex_sponge_impls() {
    const fn assert_impl<T: crate::duplex_sponge::DuplexSpongeInterface>() {}
    const fn assert_init_impl<T: crate::duplex_sponge::DuplexSpongeInit>() {}

    #[cfg(feature = "turboshake128")]
    {
        assert_impl::<Shake128>();
        assert_impl::<TurboShake128>();
        assert_init_impl::<Shake128>();
        assert_init_impl::<TurboShake128>();
    }
    assert_impl::<super::Hash<sha2::Sha256>>();
    assert_init_impl::<super::Hash<sha2::Sha256>>();
    #[cfg(feature = "keccak")]
    {
        assert_impl::<Keccak>();
        assert_init_impl::<Keccak>();
    }
    #[cfg(feature = "ascon")]
    assert_impl::<Ascon12>();
}
