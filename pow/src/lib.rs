#[cfg(feature = "blake3")]
pub mod blake3;
#[cfg(feature = "keccak")]
pub mod keccak;

/// Standalone proof-of-work grinder that can work with any byte challenge.
///
/// This structure provides a clean separation between the PoW solving logic
/// and the transcript/sponge operations.
pub struct PoWGrinder<S: PowStrategy> {
    strategy: S,
}

impl<S: PowStrategy> PoWGrinder<S> {
    /// Creates a new PoW grounder with the given challenge and difficulty.
    ///
    /// # Arguments
    /// * `challenge` - A 32-byte challenge array
    /// * `bits` - The difficulty in bits (logarithm of expected work)
    #[must_use]
    pub fn new(challenge: [u8; 32], bits: f64) -> Self {
        Self {
            strategy: S::new(challenge, bits),
        }
    }

    /// Attempts to find a nonce that satisfies the proof-of-work requirement.
    ///
    /// Returns the minimal nonce that makes the hash fall below the target threshold,
    /// or None if no valid nonce is found (extremely unlikely for reasonable difficulty).
    pub fn grind(&mut self) -> Option<PoWSolution> {
        self.strategy.solve()
    }

    /// Verifies that a given nonce satisfies the proof-of-work requirement.
    pub fn verify(&mut self, nonce: u64) -> bool {
        self.strategy.check(nonce)
    }
}

pub struct PoWSolution {
    pub challenge: [u8; 32],
    pub nonce: u64,
}

/// Convenience functions for using PoW with byte arrays.
pub mod convenience {
    use crate::{PoWGrinder, PoWSolution, PowStrategy};

    /// Performs proof-of-work on a challenge and returns the solution.
    ///
    /// This is a simple wrapper that creates a grounder and immediately grinds.
    #[must_use]
    pub fn grind_pow<S: PowStrategy>(challenge: [u8; 32], bits: f64) -> Option<PoWSolution> {
        let mut grounder = PoWGrinder::<S>::new(challenge, bits);
        grounder.grind()
    }

    /// Verifies a proof-of-work nonce.
    #[must_use]
    pub fn verify_pow<S: PowStrategy>(challenge: [u8; 32], bits: f64, nonce: u64) -> bool {
        let mut grounder = PoWGrinder::<S>::new(challenge, bits);
        grounder.verify(nonce)
    }
}

pub trait PowStrategy: Clone + Sync {
    /// Creates a new proof-of-work challenge.
    /// The `challenge` is a 32-byte array that represents the challenge.
    /// The `bits` is the binary logarithm of the expected amount of work.
    /// When `bits` is large (i.e. close to 64), a valid solution may not be found.
    fn new(challenge: [u8; 32], bits: f64) -> Self;

    /// Check if the `nonce` satisfies the challenge.
    fn check(&mut self, nonce: u64) -> bool;

    /// Builds a solution given the input nonce
    fn solution(&self, nonce: u64) -> PoWSolution;

    /// Finds the minimal `nonce` that satisfies the challenge.
    #[cfg(not(feature = "parallel"))]
    fn solve(&mut self) -> Option<PoWSolution> {
        (0..=u64::MAX)
            .find(|&nonce| self.check(nonce))
            .map(|nonce| self.solution(nonce))
    }

    #[cfg(feature = "parallel")]
    fn solve(&mut self) -> Option<PoWSolution> {
        // Split the work across all available threads.
        // Use atomics to find the unique deterministic lowest satisfying nonce.

        use std::sync::atomic::{AtomicU64, Ordering};

        use rayon::broadcast;
        let global_min = AtomicU64::new(u64::MAX);
        let _ = broadcast(|ctx| {
            let mut worker = self.clone();
            let nonces = (ctx.index() as u64..).step_by(ctx.num_threads());
            for nonce in nonces {
                // Use relaxed ordering to eventually get notified of another thread's solution.
                // (Propagation delay should be in the order of tens of nanoseconds.)
                if nonce >= global_min.load(Ordering::Relaxed) {
                    break;
                }
                if worker.check(nonce) {
                    // We found a solution, store it in the global_min.
                    // Use fetch_min to solve race condition with simultaneous solutions.
                    global_min.fetch_min(nonce, Ordering::SeqCst);
                    break;
                }
            }
        });
        let nonce = global_min.load(Ordering::SeqCst);
        self.check(nonce).then(|| self.solution(nonce))
    }
}
