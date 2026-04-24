//! Sponge shape and DSFS security-parameter bookkeeping for duplex sponges.

use crate::{DuplexSponge, Permutation};

/// Sponge parameters needed to evaluate DSFS security bounds.
#[derive(Debug, Clone, Copy)]
pub struct SpongeParams {
    /// Alphabet size `|Sigma|`.
    pub alphabet_size: f64,
    /// Sponge capacity `c`.
    pub capacity: u64,
    /// Sponge rate `r`.
    pub rate: u64,
    /// Codec/domain parameter `delta`.
    pub delta: u64,
}

/// Parameters for the standard sponge used by this crate (`Keccak-f[1600]`, rate 136).
///
/// Matches [`DuplexSpongeParamsExt::sponge_params`] on a default [`Keccak`] duplex sponge.
pub const STD_SPONGE_PARAMS: SpongeParams = SpongeParams {
    alphabet_size: 256.0,
    capacity: 64,
    rate: 136,
    delta: 1,
};

pub type Keccak = crate::instantiations::Keccak;

/// Spongefish’s default FS transcript hash: SHAKE128 in XOF duplex mode (`std_prover` / `std_verifier`).
///
/// Use with [`crate::compile::prove_with_sponge`] when you need byte-compatibility with
/// spongefish / σ-proofs `Nizk` transcript defaults.
pub type StdHash = crate::StdHash;

/// Compilation-layer identifier fed into [`spongefish::DomainSeparator::derive`] together with the
/// IA `protocol_id` and encoded session (length-prefixed SHA-512 in spongefish).
///
/// Must distinguish every configuration that affects the compiled NARG / DSFS bounds (sponge
/// shape, transcript format, etc.).
pub trait SpongeInfo: super::compile::ByteDuplexSponge {
    const SPONGE_INFO: &'static [u8];
}

impl SpongeInfo for Keccak {
    const SPONGE_INFO: &'static [u8] = b"dsfs/v2/keccak-f1600-r136c64";
}

impl SpongeInfo for StdHash {
    const SPONGE_INFO: &'static [u8] = b"dsfs/v2/shake128-r168c32";
}

/// Bookkeeping parameters for DSFS bounds when the transcript uses [`StdHash`] (SHAKE128 XOF).
///
/// The XOF duplex in spongefish does not expose a fixed classical sponge width; this uses the
/// rate from σ-proofs’ session-id helper (`RATE = 168`, SHAKE padding block) and treats capacity
/// as **32 bytes (256 bits)** for conservative bound evaluation. Prefer [`STD_SPONGE_PARAMS`] for
/// the default Keccak-`p[1600]` construction used in Argus.
pub const STD_HASH_SPONGE_PARAMS: SpongeParams = SpongeParams {
    alphabet_size: 256.0,
    capacity: 32,
    rate: 168,
    delta: 1,
};

/// Extension trait: derive [`SpongeParams`] for DSFS security bounds from a duplex sponge’s
/// width and rate (`capacity = width - rate`, byte alphabet, `delta = 1`).
pub trait DuplexSpongeParamsExt {
    fn sponge_params(&self) -> SpongeParams;
}

impl<P, const WIDTH: usize, const RATE: usize> DuplexSpongeParamsExt
    for DuplexSponge<P, WIDTH, RATE>
where
    P: Permutation<WIDTH>,
{
    fn sponge_params(&self) -> SpongeParams {
        SpongeParams {
            alphabet_size: 256.0,
            capacity: (WIDTH - RATE) as u64,
            rate: RATE as u64,
            delta: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DuplexSpongeParamsExt, Keccak, STD_HASH_SPONGE_PARAMS, STD_SPONGE_PARAMS};

    #[test]
    fn keccak_default_matches_std_bookkeeping() {
        let k = Keccak::default();
        let p = k.sponge_params();
        assert_eq!(p.rate, STD_SPONGE_PARAMS.rate);
        assert_eq!(p.capacity, STD_SPONGE_PARAMS.capacity);
    }

    #[test]
    fn std_hash_bookkeeping_is_conservative() {
        assert!(STD_HASH_SPONGE_PARAMS.capacity < STD_SPONGE_PARAMS.capacity);
    }
}
