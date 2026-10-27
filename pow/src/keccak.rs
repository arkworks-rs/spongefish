use ::keccak::{Keccak, State1600};

use super::PowStrategy;
use crate::difficulty_target;

#[derive(Clone, Copy)]
pub struct KeccakPoW {
    challenge: [u64; 4],
    threshold: u64,
    state: [u64; 25],
}

impl KeccakPoW {
    /// Create a new `KeccakPoW` instance with a given challenge and difficulty.
    ///
    /// # Panics
    /// - If `bits` is not in the range `0..60`.
    pub fn new(challenge: [u8; 32], bits: u32) -> Self {
        let threshold = difficulty_target(bits);
        Self {
            challenge: bytemuck::cast(challenge),
            threshold,
            state: [0; 25],
        }
    }
}

impl PowStrategy for KeccakPoW {
    fn check(&mut self, nonce: u64) -> bool {
        self.state[..4].copy_from_slice(&self.challenge);
        self.state[4] = nonce;
        for s in self.state.iter_mut().skip(5) {
            *s = 0;
        }
        f1600(&mut self.state);
        self.state[0] <= self.threshold
    }
}

fn f1600(state: &mut State1600) {
    Keccak::new().with_f1600(|f1600| f1600(state));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{convenience::*, PoWGrinder};

    fn reference_word(seed: [u8; 32], nonce: u64) -> u64 {
        let mut state = [0u64; 25];
        for (word, bytes) in state.iter_mut().zip(seed.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*bytes);
        }
        state[4] = nonce;
        Keccak::new().with_f1600(|permute| permute(&mut state));
        state[0]
    }

    #[test]
    fn predicate_matches_raw_permutation_and_inclusive_threshold() {
        // Keccak-f[1600] zero-state known answer, independent of the grinder.
        assert_eq!(reference_word([0; 32], 0), 0xf125_8f79_40e1_dde7);
        for seed in [[0; 32], core::array::from_fn(|i| i as u8)] {
            let mut pow = KeccakPoW::new(seed, 0);
            for nonce in [0, 1, u64::MAX] {
                let word = reference_word(seed, nonce);
                pow.threshold = word;
                assert!(pow.check(nonce));
                assert_eq!(pow.state[0], word);
                assert!(word > 0);
                pow.threshold = word - 1;
                assert!(!pow.check(nonce));
            }
        }
    }

    #[test]
    fn grinders_return_the_reference_minimum() {
        for bits in [0, 8, 10] {
            let seed = [42; 32];
            let threshold = u64::MAX >> bits;
            let expected = (0..=u64::MAX)
                .find(|&nonce| reference_word(seed, nonce) <= threshold)
                .unwrap();
            let mut grinder = PoWGrinder::new(KeccakPoW::new(seed, bits));
            assert_eq!(grinder.grind(), Some(expected));
            assert_eq!(grind_pow(KeccakPoW::new(seed, bits)), Some(expected));
            assert!(verify_pow(KeccakPoW::new(seed, bits), expected));
            #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
            for workers in [1, 3, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                assert_eq!(pool.install(|| grinder.grind_parallel()), Some(expected));
            }
        }
    }

    #[test]
    #[should_panic(expected = "bits must be smaller than 60")]
    fn rejects_unsupported_difficulty() {
        let _ = KeccakPoW::new([0; 32], 60);
    }
}
