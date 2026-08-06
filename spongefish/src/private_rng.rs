use core::fmt;

use crate::{
    duplex_sponge::DuplexSpongeInit, instantiations::XofRate, Decoding, DuplexSpongeInterface,
    StdHash,
};

/// Best-effort seed wiping; a guarantee only with the `zeroize` feature.
fn wipe_seed(seed: &mut [u8; PrivateRng::SEED_LEN]) {
    #[cfg(feature = "zeroize")]
    zeroize::Zeroize::zeroize(seed);
    #[cfg(not(feature = "zeroize"))]
    seed.fill(0);
}

/// The prover's private randomness: a duplex sponge ([`StdHash`]) seeded from
/// the operating system's entropy source (or an explicit seed).
///
/// # Compartmentalization
///
/// The seed is absorbed via the `Init` pattern of draft-irtf-cfrg-fiat-shamir:
/// it occupies its own rate block and is permuted **before any other operation
/// touches the state**. Entropy mixed in later ([`PrivateRng::mix_entropy`])
/// receives the same treatment: each mix is zero-padded to a rate-block
/// boundary and permuted before any output is drawn.
///
/// # Interoperability with `rand`
///
/// With the optional `rand` feature, [`PrivateRng`] implements the
/// `rand_core` RNG traits (`TryRng` with infallible error and the
/// `TryCryptoRng` marker, hence also the blanket `Rng` / `CryptoRng`), so it
/// can be passed to ecosystem samplers (`ff::Field::random`, arkworks'
/// `UniformRand`, ...).
pub struct PrivateRng {
    sponge: StdHash,
}

impl PrivateRng {
    /// The byte length of the RNG seed.
    pub const SEED_LEN: usize = 32;

    const RATE: usize = <::turboshake::TurboShake128 as XofRate>::RATE;

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
        let mut seed = [0u8; Self::SEED_LEN];
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
    pub fn from_seed(mut seed: [u8; Self::SEED_LEN]) -> Self {
        let rng = Self {
            sponge: StdHash::init(&seed),
        };
        wipe_seed(&mut seed);
        rng
    }

    /// Mixes additional entropy into the RNG state, zero-padded into its own
    /// permuted rate block(s).
    pub fn mix_entropy(&mut self, data: &[u8]) {
        const ZEROS: [u8; PrivateRng::RATE] = [0u8; PrivateRng::RATE];
        if data.is_empty() {
            return;
        }
        self.sponge.absorb(data);
        let rem = data.len() % Self::RATE;
        if rem != 0 {
            self.sponge.absorb(&ZEROS[..Self::RATE - rem]);
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

// The seed must fit in the rate block that the `Init` pattern dedicates to it.
const _: () = assert!(PrivateRng::SEED_LEN <= PrivateRng::RATE);

impl fmt::Debug for PrivateRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateRng")
    }
}

#[cfg(feature = "rand")]
impl rand_core::TryRng for PrivateRng {
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
impl rand_core::TryCryptoRng for PrivateRng {}
