use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroizing;

#[cfg(feature = "turboshake128")]
use crate::DefaultHash;
use crate::{duplex_sponge::DuplexSpongeInit, FromUniform};

/// The byte length of a [`PrivateRng`] seed.
pub const SEED_LEN: usize = 32;

/// The prover's private randomness.
///
/// Seeded from the operating system's entropy source (or an explicit seed),
/// the prover's private randomness is produced by default via [`DefaultHash`],
/// and any byte-oriented [`DuplexSpongeInit`] works.
///
/// # Compartmentalization
///
/// The seed is absorbed via the construction's `Init` convention.
/// Additional entropy may be absorbed via [`DuplexSpongeInit::absorb_block`], whose
/// behavior depends on the construction; its default implementation simply
/// calls `absorb`.
///
/// With the provided SHAKE128 and TurboSHAKE128 suites, initialization ends
/// at a rate boundary, squeezing leaves the absorb position unchanged, and
/// each entropy mix is zero-filled to a rate boundary. Each 32-byte mix
/// therefore occupies its own rate block in this RNG. This is not a generic
/// guarantee of [`DuplexSpongeInit`].
///
/// # Interoperability with `rand`
///
/// With the optional `rand` feature, [`PrivateRng`] implements the
/// `rand_core` RNG traits (`TryRng` with infallible error and the
/// `TryCryptoRng` marker, hence also the blanket `Rng` / `CryptoRng`), so it
/// can be passed to ecosystem samplers (`ff::Field::random`, arkworks'
/// `UniformRand`, ...).
pub struct PrivateRng<
    #[cfg(feature = "turboshake128")] H: DuplexSpongeInit<U = u8> = DefaultHash,
    #[cfg(not(feature = "turboshake128"))] H: DuplexSpongeInit<U = u8>,
> {
    sponge: H,
}

impl<H: DuplexSpongeInit<U = u8>> PrivateRng<H> {
    /// The byte length of the RNG seed.
    pub const SEED_LEN: usize = SEED_LEN;

    /// Seeds the RNG with 32 bytes from the operating system's entropy source.
    ///
    /// # Security
    ///
    /// If the entropy source is compromised or not cryptographically secure,
    /// the resulting non-interactive argument will lose zero-knowledge.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's entropy source fails.
    #[cfg(feature = "getrandom")]
    pub fn from_os_entropy() -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        getrandom::fill(seed.as_mut()).expect("operating system entropy source failed");
        Self {
            sponge: H::init(&seed),
        }
    }

    /// Builds a **deterministic** CSRNG from a seed.
    ///
    /// # Security
    ///
    /// This function is meant to be used for test vectors and reproducible tests only.
    /// Proving with a fixed or reused seed compromises zero-knowledge.
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        let seed = Zeroizing::new(seed);
        Self {
            sponge: H::init(&seed),
        }
    }

    /// Mixes additional entropy into the RNG state.
    ///
    /// The fixed-width seed is passed to [`DuplexSpongeInit::absorb_block`].
    /// The provided SHAKE128 and TurboSHAKE128 suites zero-fill each mix to
    /// its own rate block in this RNG; other constructions use their own
    /// absorption conventions.
    pub fn mix_entropy(&mut self, data: &[u8; SEED_LEN]) {
        self.sponge.absorb_block(data);
    }

    /// Fills `dest` with random bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.sponge.squeeze(dest);
    }

    /// Sample a value through its [`FromUniform`] codec.
    ///
    /// Use the internal RNG to squeeze a [`Repr`][FromUniform::Repr] and decode it.
    /// [`crate::ByteArray`] wipes itself on drop; a custom `Repr` must erase its own
    /// storage, and a decoder any copies it makes.
    pub fn sample<T: FromUniform>(&mut self) -> T {
        let mut buf = T::Repr::default();
        self.fill_bytes(buf.as_mut());
        T::from_uniform(buf)
    }

    /// Samples `n` values through their [`FromUniform`] map.
    pub fn sample_vec<T: FromUniform>(&mut self, n: usize) -> Vec<T> {
        (0..n).map(|_| self.sample()).collect()
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
        Ok(self.sample())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.sample())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        Self::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand")]
impl<H: DuplexSpongeInit<U = u8>> rand_core::TryCryptoRng for PrivateRng<H> {}

#[cfg(all(test, feature = "turboshake128"))]
mod tests {
    use digest::{ExtendableOutput, Update, XofReader};

    use super::{PrivateRng, SEED_LEN};
    use crate::instantiations::{XofRate, XOF};

    #[test]
    fn xof_entropy_mixes_occupy_separate_blocks_across_squeezes() {
        fn check<H: ExtendableOutput + Clone + Default + XofRate>()
        where
            H::Reader: Clone,
        {
            let seed = [7; SEED_LEN];
            let mut rng = PrivateRng::<XOF<H>>::from_seed(seed);
            // Independent reference: hash explicit full blocks for the seed
            // and every mix, without using XOF::init or absorb_block.
            let padding = alloc::vec![0; H::RATE - SEED_LEN];
            let mut reference = H::default();
            Update::update(&mut reference, &seed);
            Update::update(&mut reference, &padding);

            // Consecutive mixes, empty squeezes, and squeezes across rate
            // boundaries must all preserve alignment for the next mix.
            for (round, lengths) in [[0, 0], [0, 0], [1, 32], [167, 2], [168, 169], [337, 1]]
                .into_iter()
                .enumerate()
            {
                let entropy = [round as u8; SEED_LEN];
                rng.mix_entropy(&entropy);
                Update::update(&mut reference, &entropy);
                Update::update(&mut reference, &padding);
                let mut expected_stream = reference.clone().finalize_xof();
                for length in lengths {
                    let mut got = alloc::vec![0; length];
                    let mut expected = alloc::vec![0; length];
                    rng.fill_bytes(&mut got);
                    expected_stream.read(&mut expected);
                    assert_eq!(got, expected, "mix {round}, squeeze length {length}");
                }
            }
        }

        check::<shake::Shake128>();
        check::<turboshake::TurboShake128>();
    }
}
