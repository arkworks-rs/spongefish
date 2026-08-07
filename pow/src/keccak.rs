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
    #[allow(clippy::cast_sign_loss)]
    fn new(challenge: [u8; 32], bits: f64) -> Self {
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
