pub mod blake3;
pub mod keccak;

use spongefish::{
    ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, DuplexSpongeInterface,
    ProofError, ProofResult, ProverState, Unit, UnitToBytes, VerifierState,
};

/// [`spongefish::DomainSeparator`] for proof-of-work challenges.
pub trait PoWDomainSeparator {
    /// Adds a [`PoWChallenge`] to the [`spongefish::DomainSeparator`].
    ///
    /// In order to squeeze a proof-of-work challenge, we extract a 32-byte challenge using
    /// the byte interface, and then we find a 16-byte nonce that satisfies the proof-of-work.
    /// The nonce a 64-bit integer encoded as an unsigned integer and written in big-endian and added
    /// to the protocol transcript as the nonce for the proof-of-work.
    ///
    /// The number of bits used for the proof of work are **not** encoded within the [`spongefish::DomainSeparator`].
    /// It is up to the implementor to change the domain separator or the label in order to reflect changes in the proof
    /// in order to preserve simulation extractability.
    fn challenge_pow(self, label: &str) -> Self;
}

impl<DomainSeparator> PoWDomainSeparator for DomainSeparator
where
    DomainSeparator: ByteDomainSeparator,
{
    fn challenge_pow(self, label: &str) -> Self {
        // 16 bytes challenge and 16 bytes nonce (that will be written)
        self.challenge_bytes(32, label).add_bytes(8, "pow-nonce")
    }
}

pub trait PoWChallenge {
    /// Extension trait for generating a proof-of-work challenge.
    fn challenge_pow<S: PowStrategy>(&mut self, bits: f64) -> ProofResult<()>;
}

impl<H, U, R> PoWChallenge for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: rand::CryptoRng + rand::RngCore,
    ProverState<H, U, R>: BytesToUnitSerialize + UnitToBytes,
{
    fn challenge_pow<S: PowStrategy>(&mut self, bits: f64) -> ProofResult<()> {
        let challenge = self.challenge_bytes()?;
        let nonce = S::new(challenge, bits)
            .solve()
            .ok_or(ProofError::InvalidProof)?;
        self.add_bytes(&nonce.to_be_bytes())?;
        Ok(())
    }
}

impl<'a, H, U> PoWChallenge for VerifierState<'a, H, U>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    VerifierState<'a, H, U>: BytesToUnitDeserialize + UnitToBytes,
{
    fn challenge_pow<S: PowStrategy>(&mut self, bits: f64) -> ProofResult<()> {
        let challenge = self.challenge_bytes()?;
        let nonce = u64::from_be_bytes(self.next_bytes()?);
        if S::new(challenge, bits).check(nonce) {
            Ok(())
        } else {
            Err(ProofError::InvalidProof)
        }
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

    /// Finds the minimal `nonce` that satisfies the challenge.
    #[cfg(not(feature = "parallel"))]
    fn solve(&mut self) -> Option<u64> {
        // TODO: Parallel default impl
        (0u64..).find_map(|nonce| if self.check(nonce) { Some(nonce) } else { None })
    }

    #[cfg(feature = "parallel")]
    fn solve(&mut self) -> Option<u64> {
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
        match global_min.load(Ordering::SeqCst) {
            u64::MAX => self.check(u64::MAX).then_some(u64::MAX),
            nonce => Some(nonce),
        }
    }
}
