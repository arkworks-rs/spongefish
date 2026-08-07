use core::fmt;

use crate::{duplex_sponge::DuplexSpongeInit, Decoding, StdHash};

/// The byte length of a [`PrivateRng`] seed.
pub const SEED_LEN: usize = 32;

/// Best-effort seed wiping; a guarantee only with the `zeroize` feature.
fn wipe_seed(seed: &mut [u8; SEED_LEN]) {
    #[cfg(feature = "zeroize")]
    zeroize::Zeroize::zeroize(seed);
    #[cfg(not(feature = "zeroize"))]
    seed.fill(0);
}

/// The prover's private randomness: a byte-oriented duplex sponge seeded from
/// the operating system's entropy source (or an explicit seed).
///
/// Generic over the sponge: the default is [`StdHash`], and any byte-oriented
/// [`DuplexSpongeInit`] works — the RNG's whole interface is bytes, so unlike
/// the public coins it does not follow the protocol's alphabet. An algebraic
/// prover keeps a byte RNG and maps its output into the field itself. The
/// output stream is exactly
/// `H::init(seed)` followed by squeezes, so a seeded
/// `PrivateRng<H>` reproduces the deterministic byte stream of the
/// corresponding suite (e.g. the test-vector DRNGs of
/// draft-irtf-cfrg-sigma-protocols over
/// [`Shake128`][crate::instantiations::Shake128]).
///
/// # Compartmentalization
///
/// The seed is absorbed via the construction's `Init` convention: on the XOF
/// suites it occupies its own rate block and is permuted **before any other
/// operation touches the state**. Entropy mixed in later
/// ([`PrivateRng::mix_entropy`]) is compartmentalized the same way through
/// [`DuplexSpongeInit::absorb_block`].
///
/// # Interoperability with `rand`
///
/// With the optional `rand` feature, [`PrivateRng`] implements the
/// `rand_core` RNG traits (`TryRng` with infallible error and the
/// `TryCryptoRng` marker, hence also the blanket `Rng` / `CryptoRng`), so it
/// can be passed to ecosystem samplers (`ff::Field::random`, arkworks'
/// `UniformRand`, ...).
pub struct PrivateRng<H: DuplexSpongeInit<U = u8> = StdHash> {
    sponge: H,
}

impl<H: DuplexSpongeInit<U = u8>> PrivateRng<H> {
    /// The byte length of the RNG seed.
    pub const SEED_LEN: usize = SEED_LEN;

    /// Seeds the RNG with 32 bytes from the operating system's entropy source.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's entropy source fails: proceeding to
    /// prove with broken randomness would compromise zero-knowledge (and, for
    /// sigma protocols, leak the witness).
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn from_os_entropy() -> Self {
        let mut seed = [0u8; SEED_LEN];
        getrandom::fill(&mut seed).expect("operating system entropy source failed");
        let rng = Self::from_seed(seed);
        wipe_seed(&mut seed);
        rng
    }

    /// Builds a **deterministic** RNG from a seed.
    ///
    /// # Safety
    ///
    /// This is for test vectors and reproducible tests only. Proving with a
    /// fixed or reused seed compromises zero-knowledge.
    #[must_use]
    pub fn from_seed(mut seed: [u8; SEED_LEN]) -> Self {
        let rng = Self {
            sponge: H::init(&seed),
        };
        wipe_seed(&mut seed);
        rng
    }

    /// Mixes additional entropy into the RNG state, compartmentalized per the
    /// sponge construction ([`DuplexSpongeInit::absorb_block`]).
    pub fn mix_entropy(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.sponge.absorb_block(data);
        }
    }

    /// Fills `dest` with random bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.sponge.squeeze(dest);
    }

    /// Samples a value through its [`Decoding`] codec — the same
    /// distribution-preserving path used for verifier messages.
    pub fn sample<T: Decoding<[u8]>>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.fill_bytes(buf.as_mut());
        T::decode(buf)
    }
}

impl<H: DuplexSpongeInit<U = u8>> fmt::Debug for PrivateRng<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateRng")
    }
}

#[cfg(feature = "rand")]
impl<H: DuplexSpongeInit<U = u8>> rand_core::TryRng for PrivateRng<H> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        Self::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand")]
impl<H: DuplexSpongeInit<U = u8>> rand_core::TryCryptoRng for PrivateRng<H> {}
