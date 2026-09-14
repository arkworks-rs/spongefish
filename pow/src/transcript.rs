//! Proof-of-work-protected verifier messages for byte-oriented transcripts.

use spongefish::{
    Decoding, DuplexSpongeInit, DuplexSpongeInterface, ProverState, VerificationError,
    VerifierState,
};

use crate::{PoWGrinder, PowStrategy};

/// Length in bytes of the challenge squeezed for the proof-of-work grind.
const POW_CHALLENGE_BYTES: usize = 32;

/// Extension trait adding a proof-of-work-protected verifier message to a
/// Fiat-Shamir transcript over bytes (`H::U = u8`).
///
/// The prover squeezes a 32-byte grinding challenge, grinds and sends a `u64`
/// nonce, then squeezes the returned challenge `T`. The verifier repeats those
/// steps, checking the nonce before absorbing it or producing `T`.
///
/// The nonce uses Spongefish's little-endian `u64` encoding. A rejected or
/// truncated nonce poisons the verifier, so catching the error cannot turn the
/// proof into an accepted one.
///
/// # Protocol parameters
///
/// The PoW strategy, difficulty, position of this step, and decoding of `T`
/// must be fixed by the protocol and accounted for in its session tag. The
/// difficulty must not be chosen by reading an untrusted value from the proof.
/// Any soundness benefit depends on the surrounding protocol and PoW strategy.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "blake3")]
/// # {
/// use spongefish::{DefaultHash, Narg, ProverState, VerifierState};
/// use spongefish_pow::{blake3::Blake3PoW, DecodingPow};
///
/// let session_id = Narg::derive_session_id(b"example/v1/blake3-pow-8/u32");
/// let instance = 0u32;
/// let mut prover = ProverState::<DefaultHash>::new(&session_id, &instance);
/// let challenge: u32 = prover.verifier_message_pow::<u32, Blake3PoW>(8.0);
/// let proof = prover.into_narg_string();
///
/// let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof);
/// let replay = verifier.verifier_message_pow::<u32, Blake3PoW>(8.0)?;
/// assert_eq!(challenge, replay);
/// verifier.check_eof()?;
/// # }
/// # Ok::<(), spongefish::VerificationError>(())
/// ```
pub trait DecodingPow {
    /// `T` for the prover, and `Result<T, VerificationError>` for the verifier.
    type Output<T>;

    /// Squeeze a verifier message after a proof-of-work step using `S`.
    ///
    /// `bits` is the binary logarithm of the expected work, subject to the
    /// chosen strategy's supported range.
    ///
    /// # Errors
    ///
    /// The verifier returns [`VerificationError`] if the nonce is invalid,
    /// the proof is truncated, or an earlier read has poisoned the verifier.
    ///
    /// # Panics
    ///
    /// The prover panics if grinding exhausts the nonce space. Either side
    /// may panic if the strategy rejects an unsupported difficulty.
    #[must_use]
    fn verifier_message_pow<T, S>(&mut self, bits: f64) -> Self::Output<T>
    where
        T: Decoding<[u8]>,
        S: PowStrategy;
}

impl<H, R> DecodingPow for ProverState<H, R>
where
    H: DuplexSpongeInterface<U = u8>,
    R: DuplexSpongeInit<U = u8>,
{
    type Output<T> = T;

    fn verifier_message_pow<T, S>(&mut self, bits: f64) -> T
    where
        T: Decoding<[u8]>,
        S: PowStrategy,
    {
        let challenge: [u8; POW_CHALLENGE_BYTES] = self.verifier_message();
        let solution = PoWGrinder::<S>::new(challenge, bits)
            .grind()
            .expect("proof-of-work grinding exhausted the nonce space");
        self.prover_message(&solution.nonce);
        self.verifier_message()
    }
}

impl<H> DecodingPow for VerifierState<'_, H>
where
    H: DuplexSpongeInterface<U = u8>,
{
    type Output<T> = Result<T, VerificationError>;

    fn verifier_message_pow<T, S>(&mut self, bits: f64) -> Result<T, VerificationError>
    where
        T: Decoding<[u8]>,
        S: PowStrategy,
    {
        let challenge: [u8; POW_CHALLENGE_BYTES] = self.verifier_message();
        let mut grinder = PoWGrinder::<S>::new(challenge, bits);
        // Validate inside the reader boundary: failure poisons the reader and
        // prevents the rejected nonce from being absorbed into the transcript.
        self.prover_message_with(
            |reader| {
                let nonce = reader.read::<u64>()?;
                grinder
                    .verify(nonce)
                    .then_some(nonce)
                    .ok_or(VerificationError)
            },
            |nonce| nonce.to_le_bytes(),
        )?;
        Ok(self.verifier_message())
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    #[cfg(any(feature = "blake3", feature = "keccak"))]
    use spongefish::{
        instantiations::{Shake128, TurboShake128},
        Narg, ProverState,
    };
    use spongefish::{DuplexSpongeInterface, VerifierState};

    use super::DecodingPow;
    #[cfg(feature = "blake3")]
    use crate::PoWGrinder;
    use crate::{PoWSolution, PowStrategy};

    #[cfg(any(feature = "blake3", feature = "keccak"))]
    const BITS: f64 = 8.0;

    // Use different public/private sponges to exercise the refactored RNG bound.
    #[cfg(any(feature = "blake3", feature = "keccak"))]
    fn prover() -> ProverState<TurboShake128, Shake128> {
        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        ProverState::new_with_seed(&session_id, &0u32, [7; 32])
    }

    #[cfg(any(feature = "blake3", feature = "keccak"))]
    fn verifier(proof: &[u8]) -> VerifierState<'_, TurboShake128> {
        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        VerifierState::new(&session_id, &0u32, proof)
    }

    #[cfg(any(feature = "blake3", feature = "keccak"))]
    fn round_trip<S: PowStrategy>() {
        let mut prover = prover();
        prover.prover_message(&123u32);
        let first: u64 = prover.verifier_message_pow::<u64, S>(BITS);
        prover.prover_message(&456u32);
        let second: [u8; 32] = prover.verifier_message_pow::<[u8; 32], S>(BITS);
        let proof = prover.into_narg_string();
        assert_eq!(proof.len(), 4 + 8 + 4 + 8);

        let mut verifier = verifier(&proof);
        assert_eq!(verifier.prover_message::<u32>().unwrap(), 123);
        assert_eq!(
            verifier.verifier_message_pow::<u64, S>(BITS).unwrap(),
            first
        );
        assert_eq!(verifier.prover_message::<u32>().unwrap(), 456);
        assert_eq!(
            verifier.verifier_message_pow::<[u8; 32], S>(BITS).unwrap(),
            second
        );
        assert!(verifier.check_eof().is_ok());
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn blake3_round_trip() {
        round_trip::<crate::blake3::Blake3PoW>();
    }

    #[cfg(feature = "keccak")]
    #[test]
    fn keccak_round_trip() {
        round_trip::<crate::keccak::KeccakPoW>();
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn matches_manual_transcript_and_nonce_encoding() {
        use crate::blake3::Blake3PoW;

        let mut manual = prover();
        let challenge = manual.verifier_message::<[u8; 32]>();
        let solution = PoWGrinder::<Blake3PoW>::new(challenge, BITS)
            .grind()
            .unwrap();
        manual.prover_message(&solution.nonce);
        let expected = manual.verifier_message::<u64>();

        let mut bundled = prover();
        assert_eq!(
            bundled.verifier_message_pow::<u64, Blake3PoW>(BITS),
            expected
        );
        assert_eq!(bundled.into_narg_string(), solution.nonce.to_le_bytes());
        assert_eq!(manual.into_narg_string(), solution.nonce.to_le_bytes());
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn rejects_a_nonce_that_only_meets_the_lower_difficulty() {
        use crate::blake3::Blake3PoW;

        let challenge = verifier(&[]).verifier_message::<[u8; 32]>();
        let mut easy = PoWGrinder::<Blake3PoW>::new(challenge, BITS);
        let mut hard = PoWGrinder::<Blake3PoW>::new(challenge, BITS + 8.0);
        // Explicitly choose a nonce that fails the harder predicate; a valid
        // low-difficulty nonce can also satisfy a higher difficulty.
        let nonce = (0..=u64::MAX)
            .find(|&n| easy.verify(n) && !hard.verify(n))
            .unwrap();
        let proof = nonce.to_le_bytes();
        let mut easy_verifier = verifier(&proof);
        assert!(easy_verifier
            .verifier_message_pow::<u64, Blake3PoW>(BITS)
            .is_ok());
        assert!(easy_verifier.check_eof().is_ok());

        let mut hard_verifier = verifier(&proof);
        assert!(hard_verifier
            .verifier_message_pow::<u64, Blake3PoW>(BITS + 8.0)
            .is_err());
        assert!(hard_verifier.prover_messages_vec::<u8>(0).is_err());
        assert!(hard_verifier.check_eof().is_err());
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Event {
        Absorb(Vec<u8>),
        Squeeze(usize),
    }

    #[derive(Clone)]
    struct RecordingSponge(Rc<RefCell<Vec<Event>>>);

    impl DuplexSpongeInterface for RecordingSponge {
        type U = u8;

        fn absorb(&mut self, input: &[u8]) -> &mut Self {
            self.0.borrow_mut().push(Event::Absorb(input.to_vec()));
            self
        }

        fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
            self.0.borrow_mut().push(Event::Squeeze(output.len()));
            output.fill(0);
            self
        }
    }

    #[derive(Clone)]
    struct FixedPredicate<const ACCEPT: bool>;

    impl<const ACCEPT: bool> PowStrategy for FixedPredicate<ACCEPT> {
        fn new(_challenge: [u8; 32], _bits: f64) -> Self {
            Self
        }

        fn check(&mut self, _nonce: u64) -> bool {
            ACCEPT
        }

        fn solution(&self, nonce: u64) -> PoWSolution {
            PoWSolution {
                challenge: [0; 32],
                nonce,
            }
        }
    }

    #[test]
    fn rejected_nonce_is_not_absorbed_and_poisoning_survives_caught_errors() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut verifier = VerifierState::from_parts(RecordingSponge(events.clone()), &[0; 8]);
        assert!(verifier
            .verifier_message_pow::<u64, FixedPredicate<false>>(8.0)
            .is_err());
        // Only the grinding challenge was squeezed: no nonce absorption and
        // no protected challenge, even though all proof bytes were consumed.
        assert_eq!(*events.borrow(), [Event::Squeeze(32)]);
        assert!(verifier.prover_message::<u8>().is_err());
        assert!(verifier.prover_messages_vec::<u8>(0).is_err());
        assert!(verifier
            .verifier_message_pow::<u64, FixedPredicate<false>>(8.0)
            .is_err());
        assert!(verifier.check_eof().is_err());
    }

    #[test]
    fn valid_nonce_is_absorbed_before_the_protected_challenge() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let proof = 42u64.to_le_bytes();
        let mut verifier = VerifierState::from_parts(RecordingSponge(events.clone()), &proof);
        assert_eq!(
            verifier
                .verifier_message_pow::<u64, FixedPredicate<true>>(8.0)
                .unwrap(),
            0
        );
        assert_eq!(
            *events.borrow(),
            [
                Event::Squeeze(32),
                Event::Absorb(proof.to_vec()),
                Event::Squeeze(8)
            ]
        );
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn every_truncated_nonce_is_rejected() {
        for length in 0..8 {
            let events = Rc::new(RefCell::new(Vec::new()));
            let proof = vec![0; length];
            let mut verifier = VerifierState::from_parts(RecordingSponge(events.clone()), &proof);
            // Even an always-accepting predicate cannot rescue a short nonce.
            assert!(verifier
                .verifier_message_pow::<u64, FixedPredicate<true>>(8.0)
                .is_err());
            assert_eq!(*events.borrow(), [Event::Squeeze(32)]);
            assert!(verifier.check_eof().is_err());
        }
    }
}
