use blake3::{
    guts::BLOCK_LEN,
    platform::{Platform, MAX_SIMD_DEGREE},
    IncrementCounter, OUT_LEN,
};

use super::PowStrategy;
use crate::difficulty_target;

/// A SIMD-accelerated BLAKE3-based proof-of-work engine.
///
/// This struct searches for a nonce such that the first eight bytes of
/// `BLAKE3(challenge || nonce.to_le_bytes() || [0; 24])`, interpreted as a
/// little-endian `u64`, are at most the difficulty threshold.
///
/// It leverages `Platform::hash_many` for parallel hash evaluation using `MAX_SIMD_DEGREE` lanes.
#[derive(Clone, Copy)]
pub struct Blake3PoW {
    /// The 32-byte challenge seed used as a prefix to every hash input.
    challenge: [u8; 32],
    /// Difficulty target: hashes must be at most this 64-bit threshold.
    threshold: u64,
    /// Platform-specific SIMD hashing backend selected at runtime.
    platform: Platform,
    /// SIMD batch of 64-byte inputs: challenge, little-endian nonce, 24 zero bytes.
    inputs: [[u8; BLOCK_LEN]; MAX_SIMD_DEGREE],
    /// SIMD batch of hash outputs (32 bytes each).
    outputs: [u8; OUT_LEN * MAX_SIMD_DEGREE],
}

impl Blake3PoW {
    /// Create a new Blake3PoW instance with a given challenge and difficulty.
    ///
    /// The `bits` parameter controls the difficulty. A higher number means
    /// lower probability of success per nonce. This function prepares the SIMD
    /// input buffer with the challenge prefix and sets the internal threshold.
    ///
    /// # Panics
    /// - If `bits` is not in the range `0..60`.
    /// - If `BLOCK_LEN` or `OUT_LEN` do not match expected values.
    pub fn new(challenge: [u8; 32], bits: u32) -> Self {
        // BLAKE3 block size must be 64 bytes.
        assert_eq!(BLOCK_LEN, 64);
        // BLAKE3 output size must be 32 bytes.
        assert_eq!(OUT_LEN, 32);
        let threshold = difficulty_target(bits);

        // Prepare SIMD input buffer: fill each lane with the challenge prefix.
        let mut inputs = [[0u8; BLOCK_LEN]; MAX_SIMD_DEGREE];
        for input in &mut inputs {
            input[..32].copy_from_slice(&challenge);
        }

        Self {
            // Store challenge prefix.
            challenge,
            // Compute threshold: smaller means harder PoW.
            threshold,
            // Detect SIMD platform (e.g., AVX2, NEON, etc).
            platform: Platform::detect(),
            // Pre-filled SIMD inputs (nonce injected later).
            inputs,
            // Zero-initialized output buffer for SIMD hashes.
            outputs: [0; OUT_LEN * MAX_SIMD_DEGREE],
        }
    }
}

impl PowStrategy for Blake3PoW {
    /// Check if a given `nonce` satisfies the challenge.
    ///
    /// This uses the standard high-level BLAKE3 interface to ensure
    /// full compatibility with reference implementations.
    ///
    /// A nonce is valid if the first 8 bytes of the hash output,
    /// interpreted as a little-endian `u64`, are at most the internal threshold.
    fn check(&mut self, nonce: u64) -> bool {
        // Create a new BLAKE3 hasher instance.
        let mut hasher = blake3::Hasher::new();

        // Feed the challenge prefix.
        hasher.update(&self.challenge);
        // Feed the nonce as little-endian bytes.
        hasher.update(&nonce.to_le_bytes());
        // Pad the challenge and nonce to a full 64-byte BLAKE3 input block.
        hasher.update(&[0; 24]);

        // Hash the input and extract the first 8 bytes.
        let mut hash = [0u8; 8];
        hasher.finalize_xof().fill(&mut hash);

        // Check whether the result is at or below the threshold.
        u64::from_le_bytes(hash) <= self.threshold
    }

    /// Find the minimal `nonce` that satisfies the challenge.
    fn solve(&mut self) -> Option<u64> {
        (0..=u64::MAX)
            .step_by(MAX_SIMD_DEGREE)
            .find_map(|nonce| self.check_many(nonce))
    }

    /// Search for the lowest `nonce` that satisfies the challenge using parallel threads.
    ///
    /// Each thread scans disjoint chunks of the nonce space in stride-sized steps.
    /// The first thread to find a satisfying nonce updates a shared atomic minimum,
    /// and all others check against it to avoid unnecessary work.
    #[cfg(feature = "parallel")]
    fn solve_parallel(&mut self) -> Option<u64> {
        crate::search_parallel(self, MAX_SIMD_DEGREE as u64, Self::check_many)
    }
}

impl Blake3PoW {
    /// Default Blake3 initialization vector. Copied here because it is not publicly exported.
    #[allow(clippy::unreadable_literal)]
    const BLAKE3_IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];
    const BLAKE3_FLAGS: u8 = 0x0B; // CHUNK_START | CHUNK_END | ROOT

    /// Check a SIMD-width batch of nonces starting at `nonce`.
    ///
    /// Return the first nonce in the batch that satisfies the challenge threshold,
    /// or `None` if none do.
    fn check_many(&mut self, nonce: u64) -> Option<u64> {
        // Fill each SIMD input block with the challenge + nonce suffix.
        // If the batch would overflow `u64`, stop at the last representable nonce
        // and zero the remaining lanes so they never get reported as valid.
        let mut valid_lanes = MAX_SIMD_DEGREE;
        for (i, input) in self.inputs.iter_mut().enumerate() {
            let Some(batch_nonce) = nonce.checked_add(i as u64) else {
                valid_lanes = i;
                break;
            };
            input[32..40].copy_from_slice(&batch_nonce.to_le_bytes());
        }
        for input in &mut self.inputs[valid_lanes..] {
            input[32..40].fill(0);
        }

        // Create references required by `hash_many`.
        let input_refs: [&[u8; BLOCK_LEN]; MAX_SIMD_DEGREE] =
            std::array::from_fn(|i| &self.inputs[i]);

        // Perform parallel hashing over the input blocks.
        self.platform.hash_many::<BLOCK_LEN>(
            &input_refs,
            &Self::BLAKE3_IV,     // Initialization vector
            0,                    // Counter
            IncrementCounter::No, // Do not increment counter
            Self::BLAKE3_FLAGS,   // Default flags
            0,
            0, // No start/end flags
            &mut self.outputs,
        );

        // Scan results and return the first nonce at or below the threshold.
        for (i, chunk) in self
            .outputs
            .as_chunks::<OUT_LEN>()
            .0
            .iter()
            .take(valid_lanes)
            .enumerate()
        {
            let hash = u64::from_le_bytes(chunk[..8].try_into().unwrap());
            if hash <= self.threshold {
                return nonce.checked_add(i as u64);
            }
        }

        // None of the batch satisfied the condition.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{convenience::*, PoWGrinder};

    fn reference_hash(seed: [u8; 32], nonce: u64) -> [u8; OUT_LEN] {
        let mut input = [0; BLOCK_LEN];
        input[..32].copy_from_slice(&seed);
        input[32..40].copy_from_slice(&nonce.to_le_bytes());
        *blake3::hash(&input).as_bytes()
    }

    fn reference_word(seed: [u8; 32], nonce: u64) -> u64 {
        u64::from_le_bytes(reference_hash(seed, nonce)[..8].try_into().unwrap())
    }

    #[test]
    fn simd_matches_independent_hashes_including_partial_tail() {
        for seed in [[0; 32], core::array::from_fn(|i| i as u8)] {
            for base in [
                0,
                127,
                u64::MAX - MAX_SIMD_DEGREE as u64 + 1,
                u64::MAX - 1,
                u64::MAX,
            ] {
                let mut pow = Blake3PoW::new(seed, 0);
                for threshold in [
                    0,
                    u64::MAX,
                    reference_word(seed, base),
                    reference_word(seed, 0),
                ] {
                    pow.threshold = threshold;
                    let expected = (0..MAX_SIMD_DEGREE)
                        .filter_map(|lane| base.checked_add(lane as u64))
                        .find(|&nonce| reference_word(seed, nonce) <= threshold);
                    assert_eq!(
                        pow.check_many(base),
                        expected,
                        "base={base}, threshold={threshold}"
                    );
                    for lane in 0..MAX_SIMD_DEGREE {
                        if let Some(nonce) = base.checked_add(lane as u64) {
                            assert_eq!(
                                pow.outputs[lane * OUT_LEN..(lane + 1) * OUT_LEN],
                                reference_hash(seed, nonce)
                            );
                            assert_eq!(pow.check(nonce), reference_word(seed, nonce) <= threshold);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn threshold_is_inclusive_and_difficulty_is_exact() {
        let mut pow = Blake3PoW::new([7; 32], 0);
        for (bits, threshold) in [
            (0, u64::MAX),
            (1, 0x7fff_ffff_ffff_ffff),
            (32, 0xffff_ffff),
            (59, 31),
        ] {
            assert_eq!(Blake3PoW::new([7; 32], bits).threshold, threshold);
        }
        let word = reference_word([7; 32], 23);
        assert!(word > 0);
        pow.threshold = word;
        assert!(pow.check(23));
        assert_eq!(pow.check_many(23), Some(23));
        pow.threshold = word - 1;
        assert!(!pow.check(23));
        assert_ne!(pow.check_many(23), Some(23));
    }

    #[test]
    fn grinders_return_the_reference_minimum() {
        for bits in [0, 8, 10] {
            let seed = [3; 32];
            let threshold = u64::MAX >> bits;
            let expected = (0..=u64::MAX)
                .find(|&nonce| reference_word(seed, nonce) <= threshold)
                .unwrap();
            let mut grinder = PoWGrinder::new(Blake3PoW::new(seed, bits));
            assert_eq!(grinder.grind(), Some(expected));
            assert_eq!(grind_pow(Blake3PoW::new(seed, bits)), Some(expected));
            assert!(verify_pow(Blake3PoW::new(seed, bits), expected));
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
        let _ = Blake3PoW::new([0; 32], 60);
    }
}
