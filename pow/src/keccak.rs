use ::keccak::{Keccak, State1600};

use super::PowStrategy;
use crate::PoWSolution;

#[derive(Clone, Copy)]
pub struct KeccakPoW {
    challenge: [u64; 4],
    threshold: u64,
    state: [u64; 25],
}

impl PowStrategy for KeccakPoW {
    /// Create a new `KeccakPoW` instance with a given challenge and difficulty.
    ///
    /// # Panics
    /// - If `bits` is not in the range `[0.0, 60.0)`.
    #[allow(clippy::cast_sign_loss)]
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        // The difficulty must stay in a range where `2^(64 - bits)` is a meaningful
        // `u64` threshold. With negative `bits` the threshold exceeds `2^64` and
        // saturates to `u64::MAX` on the cast below, so *every* nonce verifies: a
        // silent no-op proof of work. `bits == 0.0` is the explicit "no grinding"
        // setting and stays allowed. The upper bound mirrors `Blake3PoW`: both
        // engines compare a single little-endian 64-bit word against the threshold,
        // so the representable range is identical, and past ~60 bits the expected
        // grinding cost is already out of reach anyway.
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");

        let threshold = (64.0 - bits).exp2().ceil() as u64;
        Self {
            challenge: bytemuck::cast(challenge),
            threshold,
            state: [0; 25],
        }
    }

    fn solution(&self, nonce: u64) -> PoWSolution {
        PoWSolution {
            challenge: bytemuck::cast(self.challenge),
            nonce,
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        self.state[..4].copy_from_slice(&self.challenge);
        self.state[4] = nonce;
        for s in self.state.iter_mut().skip(5) {
            *s = 0;
        }
        f1600(&mut self.state);
        self.state[0] < self.threshold
    }
}

fn f1600(state: &mut State1600) {
    Keccak::new().with_f1600(|f1600| f1600(state));
}

#[test]
fn test_pow_keccak() {
    use crate::{convenience::*, PoWGrinder};

    const BITS: f64 = 10.0;

    // Test with a fixed challenge
    let challenge = [42u8; 32];

    // Generate a proof-of-work solution
    let solution = grind_pow::<KeccakPoW>(challenge, BITS).expect("Should find a valid solution");

    // Grinding is deterministic: it returns the minimal satisfying nonce, so
    // re-grinding the same challenge must yield the very same solution.
    let mut grinder = PoWGrinder::<KeccakPoW>::new(challenge, BITS);
    let solution2 = grinder.grind().expect("Should find a valid solution");
    assert_eq!(solution.nonce, solution2.nonce);

    // And the nonce must verify against the original challenge.
    assert!(verify_pow::<KeccakPoW>(challenge, BITS, solution.nonce));
}

/// A negative difficulty would saturate the threshold to `u64::MAX` and make every
/// nonce verify, so it must be rejected loudly instead.
#[test]
#[should_panic(expected = "bits must be smaller than 60")]
fn test_keccak_rejects_negative_bits() {
    let _ = <KeccakPoW as PowStrategy>::new([0u8; 32], -1.0);
}

/// Difficulties at or above 60 bits are out of the supported range.
#[test]
#[should_panic(expected = "bits must be smaller than 60")]
fn test_keccak_rejects_excessive_bits() {
    let _ = <KeccakPoW as PowStrategy>::new([0u8; 32], 60.0);
}

/// A difficulty inside the supported range still grinds and verifies.
#[test]
fn test_keccak_valid_difficulty_round_trip() {
    use crate::convenience::*;

    let challenge = [7u8; 32];
    for bits in [0.0, 1.0, 8.0, 12.0] {
        let solution =
            grind_pow::<KeccakPoW>(challenge, bits).expect("Should find a valid solution");
        assert!(verify_pow::<KeccakPoW>(challenge, bits, solution.nonce));
        assert_eq!(solution.challenge, challenge);
    }
}
