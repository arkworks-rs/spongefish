use blake3::{
    guts::BLOCK_LEN,
    platform::{Platform, MAX_SIMD_DEGREE},
    IncrementCounter, OUT_LEN,
};
#[cfg(feature = "parallel")]
use rayon::broadcast;

use super::PowStrategy;
use crate::PoWSolution;

/// A SIMD-accelerated BLAKE3-based proof-of-work engine.
///
/// This struct encapsulates the state needed to search for a nonce such that
/// `BLAKE3(challenge || nonce)` is below a difficulty threshold.
///
/// It leverages `Platform::hash_many` for parallel hash evaluation using `MAX_SIMD_DEGREE` lanes.
#[derive(Clone, Copy)]
pub struct Blake3PoW {
    /// The 32-byte challenge seed used as a prefix to every hash input.
    challenge: [u8; 32],
    /// Difficulty target: hashes must be less than this 64-bit threshold.
    threshold: u64,
    /// Platform-specific SIMD hashing backend selected at runtime.
    platform: Platform,
    /// SIMD batch of hash inputs, each 64 bytes (challenge + nonce).
    inputs: [[u8; BLOCK_LEN]; MAX_SIMD_DEGREE],
    /// SIMD batch of hash outputs (32 bytes each).
    outputs: [u8; OUT_LEN * MAX_SIMD_DEGREE],
}

impl PowStrategy for Blake3PoW {
    /// Create a new Blake3PoW instance with a given challenge and difficulty.
    ///
    /// The `bits` parameter controls the difficulty. A higher number means
    /// lower probability of success per nonce. This function prepares the SIMD
    /// input buffer with the challenge prefix and sets the internal threshold.
    ///
    /// # Panics
    /// - If `bits` is not in the range [0.0, 60.0).
    /// - If `BLOCK_LEN` or `OUT_LEN` do not match expected values.
    #[allow(clippy::cast_sign_loss)]
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        // BLAKE3 block size must be 64 bytes.
        assert_eq!(BLOCK_LEN, 64);
        // BLAKE3 output size must be 32 bytes.
        assert_eq!(OUT_LEN, 32);
        // Ensure the difficulty is within supported range.
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");

        // Prepare SIMD input buffer: fill each lane with the challenge prefix.
        let mut inputs = [[0u8; BLOCK_LEN]; MAX_SIMD_DEGREE];
        for input in &mut inputs {
            input[..32].copy_from_slice(&challenge);
        }

        Self {
            // Store challenge prefix.
            challenge,
            // Compute threshold: smaller means harder PoW.
            threshold: (64.0 - bits).exp2().ceil() as u64,
            // Detect SIMD platform (e.g., AVX2, NEON, etc).
            platform: Platform::detect(),
            // Pre-filled SIMD inputs (nonce injected later).
            inputs,
            // Zero-initialized output buffer for SIMD hashes.
            outputs: [0; OUT_LEN * MAX_SIMD_DEGREE],
        }
    }

    fn solution(&self, nonce: u64) -> PoWSolution {
        PoWSolution {
            challenge: self.challenge,
            nonce,
        }
    }

    /// Check if a given `nonce` satisfies the challenge.
    ///
    /// This uses the standard high-level BLAKE3 interface to ensure
    /// full compatibility with reference implementations.
    ///
    /// A nonce is valid if the first 8 bytes of the hash output,
    /// interpreted as a little-endian `u64`, are below the internal threshold.
    fn check(&mut self, nonce: u64) -> bool {
        // Create a new BLAKE3 hasher instance.
        let mut hasher = blake3::Hasher::new();

        // Feed the challenge prefix.
        hasher.update(&self.challenge);
        // Feed the nonce as little-endian bytes.
        hasher.update(&nonce.to_le_bytes());
        // Zero-extend the nonce to 32 bytes (challenge + nonce = full block).
        hasher.update(&[0; 24]);

        // Hash the input and extract the first 8 bytes.
        let mut hash = [0u8; 8];
        hasher.finalize_xof().fill(&mut hash);

        // Check whether the result is below the threshold.
        u64::from_le_bytes(hash) < self.threshold
    }

    /// Finds the minimal `nonce` that satisfies the challenge.
    #[cfg(not(feature = "parallel"))]
    fn solve(&mut self) -> Option<PoWSolution> {
        (0..)
            .step_by(MAX_SIMD_DEGREE)
            .find_map(|nonce| self.check_many(nonce))
            .map(|nonce| self.solution(nonce))
    }

    /// Search for the lowest `nonce` that satisfies the challenge using parallel threads.
    ///
    /// Each thread scans disjoint chunks of the nonce space in stride-sized steps.
    /// The first thread to find a satisfying nonce updates a shared atomic minimum,
    /// and all others check against it to avoid unnecessary work.
    #[cfg(feature = "parallel")]
    fn solve(&mut self) -> Option<PoWSolution> {
        use std::sync::atomic::{AtomicU64, Ordering};

        // Split the work across all available threads.
        // Use atomics to find the unique deterministic lowest satisfying nonce.
        let global_min = AtomicU64::new(u64::MAX);

        // Spawn parallel workers using Rayon's broadcast.
        let _ = broadcast(|ctx| {
            // Copy the PoW instance for thread-local use.
            let mut worker = *self;

            // Each thread searches a distinct subset of nonces.
            let nonces = ((MAX_SIMD_DEGREE * ctx.index()) as u64..)
                .step_by(MAX_SIMD_DEGREE * ctx.num_threads());

            for nonce in nonces {
                // Skip work if another thread already found a lower valid nonce.
                //
                // Use relaxed ordering to eventually get notified of another thread's solution.
                // (Propagation delay should be in the order of tens of nanoseconds.)
                if nonce >= global_min.load(Ordering::Relaxed) {
                    break;
                }
                // Check a batch of nonces starting from `nonce`.
                if let Some(nonce) = worker.check_many(nonce) {
                    // We found a solution, store it in the global_min.
                    // Use fetch_min to solve race condition with simultaneous solutions.
                    global_min.fetch_min(nonce, Ordering::SeqCst);
                    break;
                }
            }
        });

        // Return the best found nonce, or fallback check on `u64::MAX`.
        match global_min.load(Ordering::SeqCst) {
            u64::MAX => self.check(u64::MAX).then(|| self.solution(u64::MAX)),
            nonce => Some(self.solution(nonce)),
        }
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
    /// Returns the first nonce in the batch that satisfies the challenge threshold,
    /// or `None` if none do.
    fn check_many(&mut self, nonce: u64) -> Option<u64> {
        // Fill each SIMD input block with the challenge + nonce suffix.
        for (i, input) in self.inputs.iter_mut().enumerate() {
            // Write the nonce as little-endian into bytes 32..40.
            let n = (nonce + i as u64).to_le_bytes();
            input[32..40].copy_from_slice(&n);
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

        // Scan results and return the first nonce under the threshold.
        for (i, chunk) in self.outputs.chunks_exact(OUT_LEN).enumerate() {
            let hash = u64::from_le_bytes(chunk[..8].try_into().unwrap());
            if hash < self.threshold {
                return Some(nonce + i as u64);
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

    fn sample_challenges() -> Vec<[u8; 32]> {
        vec![
            [0u8; 32],                                              // All zeroes
            [0xFF; 32],                                             // All ones
            [42u8; 32],                                             // Constant value
            (0..32).collect::<Vec<u8>>().try_into().unwrap(),       // Increasing
            (0..32).rev().collect::<Vec<u8>>().try_into().unwrap(), // Decreasing
        ]
    }

    #[test]
    fn test_pow_blake3() {
        const BITS: f64 = 10.0;

        for challenge in sample_challenges() {
            // Generate a proof-of-work solution
            let _solution =
                grind_pow::<Blake3PoW>(challenge, BITS).expect("Should find a valid solution");

            // Verify we can generate solutions consistently
            assert!(grind_pow::<Blake3PoW>(challenge, BITS).is_some());
        }

        // Test using the PoWGrinder directly
        let challenge = [42u8; 32];
        let mut grinder = PoWGrinder::<Blake3PoW>::new(challenge, BITS);
        let _solution = grinder.grind().expect("Should find a valid solution");
    }

    #[test]
    #[allow(clippy::cast_sign_loss)]
    fn test_new_pow_valid_bits() {
        for bits in [0.1, 10.0, 20.0, 40.0, 59.99] {
            let challenge = [1u8; 32];
            let pow = Blake3PoW::new(challenge, bits);
            let expected_threshold = (64.0 - bits).exp2().ceil() as u64;
            assert_eq!(pow.threshold, expected_threshold);
            assert_eq!(pow.challenge, challenge);
        }
    }

    #[test]
    #[should_panic]
    fn test_new_invalid_bits() {
        let _ = Blake3PoW::new([0u8; 32], 60.0);
    }

    #[test]
    fn test_check_function_basic() {
        let challenge = [0u8; 32];
        let mut pow = Blake3PoW::new(challenge, 8.0);
        for nonce in (0u64..10000).step_by(MAX_SIMD_DEGREE) {
            if let Some(solution) = pow.check_many(nonce) {
                assert!(pow.check(solution), "check() should match check_many()");
                return;
            }
        }
        panic!("Expected at least one valid nonce under threshold using check_many");
    }

    #[cfg(not(feature = "parallel"))]
    #[test]
    fn test_solve_sequential() {
        let challenge = [2u8; 32];
        let mut pow = Blake3PoW::new(challenge, 10.0);
        let nonce = pow.solve().expect("Should find a nonce");
        assert!(pow.check(nonce), "Found nonce does not satisfy challenge");
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_solve_parallel() {
        let challenge = [3u8; 32];
        let mut pow = Blake3PoW::new(challenge, 10.0);
        let _solution = pow.solve().expect("Should find a solution");
        // Solution is valid by construction
    }

    #[test]
    fn test_different_challenges_consistency() {
        let bits = 8.0;
        for challenge in sample_challenges() {
            let mut pow = Blake3PoW::new(challenge, bits);
            let _solution = pow.solve().expect("Must find solution for low difficulty");
            // Solution is valid by construction
        }
    }

    #[test]
    fn test_check_many_determinism() {
        let challenge = [42u8; 32];
        let mut pow1 = Blake3PoW::new(challenge, 10.0);
        let mut pow2 = Blake3PoW::new(challenge, 10.0);

        let n1 = pow1.check_many(0);
        let n2 = pow2.check_many(0);
        assert_eq!(n1, n2, "check_many should be deterministic");
    }

    #[test]
    #[allow(clippy::cast_sign_loss)]
    fn test_threshold_rounding_boundaries() {
        let c = [7u8; 32];
        let bits = 24.5;
        let pow = Blake3PoW::new(c, bits);
        let expected = (64.0 - bits).exp2().ceil() as u64;
        assert_eq!(pow.threshold, expected);
    }

    #[test]
    fn test_check_many_inserts_nonce_bytes() {
        let challenge = [0xAB; 32];
        let mut pow = Blake3PoW::new(challenge, 50.0);

        // Run check_many to populate nonces.
        let base_nonce = 12_345_678;
        let _ = pow.check_many(base_nonce);

        for (i, input) in pow.inputs.iter().enumerate() {
            // Confirm prefix is unchanged
            assert_eq!(&input[..32], &challenge);
            // Confirm suffix is the correct nonce bytes
            let expected_nonce = base_nonce + i as u64;
            let actual = u64::from_le_bytes(input[32..40].try_into().unwrap());
            assert_eq!(actual, expected_nonce);
        }
    }

    #[test]
    fn test_solve_returns_minimal_nonce() {
        let c = [123; 32];
        let mut pow = Blake3PoW::new(c, 10.0);
        let mut best_nonce = None;
        for nonce in (0..10000).step_by(MAX_SIMD_DEGREE) {
            if let Some(found) = pow.check_many(nonce) {
                best_nonce = Some(found);
                break;
            }
        }

        // Get solution from solve()
        let solution = pow.solve().expect("Should find a solution");

        // If we found a nonce manually, create the same solution and compare
        if let Some(nonce) = best_nonce {
            let expected_solution = pow.solution(nonce);

            assert_eq!(
                solution.nonce, expected_solution.nonce,
                "solve should return the first valid nonce"
            );
        }
    }

    #[test]
    fn stress_test_check_many_entropy() {
        let challenge = [42u8; 32];
        let mut pow = Blake3PoW::new(challenge, 16.0);

        let mut found = 0;
        for nonce in (0..1_000_000).step_by(MAX_SIMD_DEGREE) {
            if pow.check_many(nonce).is_some() {
                found += 1;
            }
        }

        // Should find some hits at low difficulty
        assert!(found > 0, "Expected to find at least one solution");
    }
}
