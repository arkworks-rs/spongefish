//! An interactive proof-of-work step shared by every transcript implementation.

use spongefish::{Decoding, Transcript, VerificationError};

use crate::{PoWGrinder, PowStrategy};

/// Proof-of-work-protected verifier messages for interactive transcripts.
///
/// This extension is available on every [`Transcript`], including concrete
/// [`ProverState`](spongefish::ProverState) and
/// [`VerifierState`](spongefish::VerifierState) values and the generic transcript
/// passed to [`Argument::run`](spongefish::Argument::run).
///
/// Both parties run the same protocol: obtain a 32-byte grinding challenge,
/// exchange a little-endian `u64` nonce, check it, then obtain the protected
/// verifier message. Grinding is a prover-only computation; the verifier checks
/// the received nonce without running the search.
///
/// A rejected nonce fails [`Transcript::check`], permanently rejecting the
/// verifier's transcript even if the error is caught. The protected message is
/// produced only after a successful check. Truncated nonces fail during the
/// prover-message read.
///
/// # Protocol parameters
///
/// The PoW strategy, difficulty, position of this step, and decoding of the
/// protected message must be fixed by the protocol and accounted for in its
/// session tag. The difficulty must not come from an untrusted proof value.
/// Any soundness benefit depends on the surrounding protocol and PoW strategy.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "blake3")]
/// # {
/// use spongefish::{Argument, Narg, Transcript, VerificationError, Witness};
/// use spongefish_pow::{blake3::Blake3PoW, PowTranscriptExt};
///
/// struct PowRound;
/// impl Argument for PowRound {
///     type Instance = u32;
///     type Witness = ();
///     type Output = u32;
///
///     fn run<T: Transcript>(
///         transcript: &mut T,
///         _instance: &u32,
///         _witness: Witness<&()>,
///     ) -> Result<u32, VerificationError> {
///         transcript.verifier_message_pow::<u32, Blake3PoW>(8.0)
///     }
/// }
///
/// let tag = b"example/v1/blake3-pow-8/u32";
/// let (proof, challenge) = Narg::prove::<PowRound>(tag, &0, &())?;
/// let replay = Narg::verify::<PowRound>(tag, &0, &proof)?;
/// assert_eq!(challenge, replay);
/// # }
/// # Ok::<(), spongefish::VerificationError>(())
/// ```
pub trait PowTranscriptExt: Transcript {
    /// Obtain a verifier message after a proof-of-work step using `S`.
    ///
    /// Both the prover and verifier return `Result<T, VerificationError>`.
    /// `bits` is the binary logarithm of the expected work, subject to the
    /// chosen strategy's supported range.
    ///
    /// # Errors
    ///
    /// The prover returns [`VerificationError`] if grinding exhausts the nonce
    /// space. The verifier returns it if the nonce is invalid, the proof is
    /// truncated, or an earlier read or check rejected the transcript.
    ///
    /// # Panics
    ///
    /// Either side may panic if the strategy rejects an unsupported difficulty.
    fn verifier_message_pow<T, S>(&mut self, bits: f64) -> Result<T, VerificationError>
    where
        T: Decoding,
        S: PowStrategy,
    {
        let challenge = self.verifier_message::<[u8; 32]>();
        let nonce = self
            .prover_only(|| {
                PoWGrinder::<S>::new(challenge, bits)
                    .grind()
                    .map(|solution| solution.nonce)
                    .ok_or(VerificationError)
            })
            .transpose()?;
        let nonce = self.prover_message(nonce)?;
        self.check(|| PoWGrinder::<S>::new(challenge, bits).verify(nonce))?;
        Ok(self.verifier_message())
    }
}

impl<T: Transcript + ?Sized> PowTranscriptExt for T {}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use spongefish::{
        instantiations::{Shake128, TurboShake128},
        Argument, DuplexSpongeInterface, Narg, ProverState, Transcript, VerificationError,
        VerifierState, Witness,
    };

    use super::PowTranscriptExt;
    #[cfg(feature = "blake3")]
    use crate::PoWGrinder;
    use crate::{PoWSolution, PowStrategy};

    #[cfg(any(feature = "blake3", feature = "keccak"))]
    const BITS: f64 = 8.0;

    // Use different public/private sponges to exercise the refactored RNG bound.
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
        let first: u64 = prover.verifier_message_pow::<u64, S>(BITS).unwrap();
        prover.prover_message(&456u32);
        let second: [u8; 32] = prover.verifier_message_pow::<[u8; 32], S>(BITS).unwrap();
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
    fn argument_and_direct_state_apis_produce_the_same_proof_and_challenge() {
        use crate::blake3::Blake3PoW;

        struct PowRound;
        impl Argument for PowRound {
            type Instance = u32;
            type Witness = ();
            type Output = u64;

            fn run<T: Transcript>(
                transcript: &mut T,
                _instance: &u32,
                _witness: Witness<&()>,
            ) -> Result<u64, VerificationError> {
                transcript.verifier_message_pow::<u64, Blake3PoW>(BITS)
            }
        }

        let tag = b"pow/tests/v1";
        let (proof, challenge) = Narg::prove::<PowRound>(tag, &0, &()).unwrap();
        assert_eq!(
            Narg::verify::<PowRound>(tag, &0, &proof).unwrap(),
            challenge
        );

        let mut direct = prover();
        assert_eq!(
            direct.verifier_message_pow::<u64, Blake3PoW>(BITS).unwrap(),
            challenge
        );
        assert_eq!(direct.into_narg_string(), proof);
        let mut direct = verifier(&proof);
        assert_eq!(
            direct.verifier_message_pow::<u64, Blake3PoW>(BITS).unwrap(),
            challenge
        );
        assert!(direct.check_eof().is_ok());
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
            bundled
                .verifier_message_pow::<u64, Blake3PoW>(BITS)
                .unwrap(),
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

        fn solve(&mut self) -> Option<PoWSolution> {
            assert!(!ACCEPT, "verifier must not run the nonce search");
            None
        }
    }

    #[test]
    fn exhausted_grinding_returns_an_error_without_sending_a_nonce() {
        let mut prover = prover();
        assert!(prover
            .verifier_message_pow::<u64, FixedPredicate<false>>(8.0)
            .is_err());
        assert_eq!(prover.into_narg_string(), []);
    }

    #[test]
    fn argument_cannot_accept_a_caught_pow_failure() {
        struct SwallowsFailure;
        impl Argument for SwallowsFailure {
            type Instance = u32;
            type Witness = ();
            type Output = ();

            fn run<T: Transcript>(
                transcript: &mut T,
                _instance: &u32,
                _witness: Witness<&()>,
            ) -> Result<(), VerificationError> {
                let _ = transcript.verifier_message_pow::<u64, FixedPredicate<false>>(8.0);
                Ok(())
            }
        }
        assert!(Narg::verify::<SwallowsFailure>(b"caught PoW failure", &0, &[0; 8]).is_err());
    }

    #[test]
    fn rejected_nonce_produces_no_challenge_and_poisoning_survives_caught_errors() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut verifier = VerifierState::from_parts(RecordingSponge(events.clone()), &[0; 8]);
        assert!(verifier
            .verifier_message_pow::<u64, FixedPredicate<false>>(8.0)
            .is_err());
        // The nonce is an ordinary prover message. Its failed check prevents
        // the protected challenge, even though all proof bytes were consumed.
        assert_eq!(
            *events.borrow(),
            [Event::Squeeze(32), Event::Absorb(vec![0; 8])]
        );
        assert!(verifier
            .check(|| panic!("a failed check must not run again"))
            .is_err());
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
