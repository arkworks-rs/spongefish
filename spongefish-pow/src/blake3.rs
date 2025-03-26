use super::PowStrategy;
use blake3;

use {
    blake3::{
        guts::BLOCK_LEN,
        platform::{Platform, MAX_SIMD_DEGREE},
        IncrementCounter, OUT_LEN,
    },
    std::sync::atomic::{AtomicU64, Ordering},
};

#[cfg(feature = "parallel")]
use rayon::broadcast;

#[derive(Clone, Copy)]
pub struct Blake3PoW {
    challenge: [u8; 32],
    threshold: u64,
    platform: Platform,
    inputs: [u8; BLOCK_LEN * MAX_SIMD_DEGREE],
    outputs: [u8; OUT_LEN * MAX_SIMD_DEGREE],
}

impl PowStrategy for Blake3PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert_eq!(BLOCK_LEN, 64);
        assert_eq!(OUT_LEN, 32);
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        let threshold = (64.0 - bits).exp2().ceil() as u64;
        let platform = Platform::detect();
        let mut inputs = [0; BLOCK_LEN * MAX_SIMD_DEGREE];
        for input in inputs.chunks_exact_mut(BLOCK_LEN) {
            input[..challenge.len()].copy_from_slice(&challenge);
        }
        let outputs = [0; OUT_LEN * MAX_SIMD_DEGREE];
        Self {
            challenge,
            threshold,
            platform,
            inputs,
            outputs,
        }
    }

    /// This deliberately uses the high level interface to guarantee
    /// compatibility with standard Blake3.
    fn check(&mut self, nonce: u64) -> bool {
        // Ingest the challenge and the nonce.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.challenge);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&[0; 24]); // Nonce is zero extended to 32 bytes.

        // Check if the hash is below the threshold.
        let mut result_bytes = [0; 8];
        hasher.finalize_xof().fill(&mut result_bytes);
        let result = u64::from_le_bytes(result_bytes);
        result < self.threshold
    }

    /// Finds the minimal `nonce` that satisfies the challenge.
    #[cfg(not(feature = "parallel"))]
    fn solve(&mut self) -> Option<u64> {
        (0u64..)
            .step_by(MAX_SIMD_DEGREE)
            .find_map(|nonce| self.check_many(nonce))
    }

    /// Finds the minimal `nonce` that satisfies the challenge.
    #[cfg(feature = "parallel")]
    fn solve(&mut self) -> Option<u64> {
        // Split the work across all available threads.
        // Use atomics to find the unique deterministic lowest satisfying nonce.
        let global_min = AtomicU64::new(u64::MAX);
        let _ = broadcast(|ctx| {
            let mut worker = *self;
            let nonces = ((MAX_SIMD_DEGREE * ctx.index()) as u64..)
                .step_by(MAX_SIMD_DEGREE * ctx.num_threads());
            for nonce in nonces {
                // Use relaxed ordering to eventually get notified of another thread's solution.
                // (Propagation delay should be in the order of tens of nanoseconds.)
                if nonce >= global_min.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(nonce) = worker.check_many(nonce) {
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

impl Blake3PoW {
    /// Default Blake3 initialization vector. Copied here because it is not publicly exported.
    const BLAKE3_IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];
    const BLAKE3_FLAGS: u8 = 0x0B; // CHUNK_START | CHUNK_END | ROOT

    /// Find the minimal nonce that satisfies the challenge (if any) in a
    /// length `MAX_SIMD_DEGREE` sequence of nonces starting from `nonce`.
    fn check_many(&mut self, nonce: u64) -> Option<u64> {
        for (i, input) in self.inputs.chunks_exact_mut(BLOCK_LEN).enumerate() {
            input[32..40].copy_from_slice(&(nonce + i as u64).to_le_bytes())
        }
        // `hash_many` requires an array of references. We need to construct this fresh
        // each call as we cannot store the references and mutate the array.
        let inputs: [&[u8; BLOCK_LEN]; MAX_SIMD_DEGREE] = std::array::from_fn(|i| {
            self.inputs[(i * BLOCK_LEN)..((i + 1) * BLOCK_LEN)]
                .try_into()
                .unwrap()
        });
        let counter = 0;
        let flags_start = 0;
        let flags_end = 0;
        self.platform.hash_many::<BLOCK_LEN>(
            &inputs,
            &Self::BLAKE3_IV,
            counter,
            IncrementCounter::No,
            Self::BLAKE3_FLAGS,
            flags_start,
            flags_end,
            &mut self.outputs,
        );
        for (i, input) in self.outputs.chunks_exact_mut(OUT_LEN).enumerate() {
            let result = u64::from_le_bytes(input[..8].try_into().unwrap());
            if result < self.threshold {
                return Some(nonce + i as u64);
            }
        }
        None
    }
}

#[test]
fn test_pow_blake3() {
    use crate::{
        ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, PoWChallenge,
        PoWDomainSeparator,
    };
    use spongefish::{DefaultHash, DomainSeparator};

    const BITS: f64 = 10.0;

    let domain_separator = DomainSeparator::<DefaultHash>::new("the proof of work lottery 🎰")
        .add_bytes(1, "something")
        .challenge_pow("rolling dices");

    let mut prover = domain_separator.to_prover_state();
    prover.add_bytes(b"\0").expect("Invalid DomainSeparator");
    prover.challenge_pow::<Blake3PoW>(BITS).unwrap();

    let mut verifier = domain_separator.to_verifier_state(prover.narg_string());
    let byte = verifier.next_bytes::<1>().unwrap();
    assert_eq!(&byte, b"\0");
    verifier.challenge_pow::<Blake3PoW>(BITS).unwrap();
}
