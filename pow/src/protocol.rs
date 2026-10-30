//! Proof-of-work-protected verifier messages.
//!
//! This module connects the proof-of-work utilities to the transcript API.
//! Proof of work must be bound to the generation of the next verifier message.
//! A separate proof-of-work check alone does not guarantee multiplicative soundness amplification.
//! The helper introduced here keeps nonce absorption, verification, and challenge generation together
//! to make this integration easier to get right.

use spongefish::{FromUniform, Transcript, VerificationError};

use crate::{PoWGrinder, PowStrategy};

/// Proof-of-work-protected verifier messages for interactive transcripts.
///
/// This extension is available on every [`Transcript`], including concrete
/// [`ProverState`](spongefish::ProverState) and
/// [`VerifierState`](spongefish::VerifierState) values and the generic transcript
/// passed to [`Argument::run`](spongefish::Argument::run).
///
/// Callers prepare the same proof-of-work problem on both sides, binding its seed
/// to the transcript before calling this helper. Both parties exchange a
/// little-endian `u64` nonce, check it, then obtain the protected
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
/// The PoW strategy, difficulty, position of this step, and the codec of the
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
///         let seed = transcript.verifier_message::<[u8; 32]>();
///         transcript.verifier_message_pow::<u32>(Blake3PoW::new(seed, 8))
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
    /// Obtain a verifier message after solving and checking a prepared strategy.
    ///
    /// Both the prover and verifier return `Result<T, VerificationError>`.
    /// The caller binds the strategy to the transcript, for example by squeezing
    /// a seed and constructing it with the protocol's difficulty. This helper
    /// searches sequentially and does not squeeze a seed itself.
    ///
    /// # Errors
    ///
    /// The prover returns [`VerificationError`] if grinding exhausts the nonce
    /// space. The verifier returns it if the nonce is invalid, the proof is
    /// truncated, or an earlier read or check rejected the transcript.
    fn verifier_message_pow<T: FromUniform>(
        &mut self,
        strategy: impl PowStrategy,
    ) -> Result<T, VerificationError> {
        let mut grinder = PoWGrinder::new(strategy);
        let nonce = self
            .prover_only(|| grinder.grind().ok_or(VerificationError))
            .transpose()?;
        let nonce = self.prover_message(nonce)?;
        self.check(|| grinder.verify(nonce))?;
        Ok(self.verifier_message())
    }
}

impl<T: Transcript + ?Sized> PowTranscriptExt for T {}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use spongefish::{
        instantiations::{Shake128, TurboShake128},
        Argument, DuplexSpongeInit, DuplexSpongeInterface, Narg, ProverState, Transcript,
        VerificationError, VerifierState, Witness,
    };

    use super::PowTranscriptExt;
    #[cfg(feature = "blake3")]
    use crate::PoWGrinder;
    use crate::PowStrategy;

    #[cfg(any(feature = "blake3", feature = "keccak"))]
    const BITS: u32 = 8;

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

    #[cfg(feature = "blake3")]
    #[test]
    fn interleaved_pow_steps_preserve_messages_and_challenges() {
        use crate::blake3::Blake3PoW;

        let mut prover = prover();
        prover.prover_message(&123u32);
        let first: u64 = {
            let seed = prover.verifier_message::<[u8; 32]>();
            prover.verifier_message_pow::<u64>(Blake3PoW::new(seed, BITS))
        }
        .unwrap();
        prover.prover_message(&456u32);
        let second: [u8; 32] = {
            let seed = prover.verifier_message::<[u8; 32]>();
            prover.verifier_message_pow::<[u8; 32]>(Blake3PoW::new(seed, BITS))
        }
        .unwrap();
        let proof = prover.into_narg_string();
        assert_eq!(proof.len(), 4 + 8 + 4 + 8);

        let mut verifier = verifier(&proof);
        assert_eq!(verifier.prover_message::<u32>().unwrap(), 123);
        assert_eq!(
            {
                let seed = verifier.verifier_message::<[u8; 32]>();
                verifier.verifier_message_pow::<u64>(Blake3PoW::new(seed, BITS))
            }
            .unwrap(),
            first
        );
        assert_eq!(verifier.prover_message::<u32>().unwrap(), 456);
        assert_eq!(
            {
                let seed = verifier.verifier_message::<[u8; 32]>();
                verifier.verifier_message_pow::<[u8; 32]>(Blake3PoW::new(seed, BITS))
            }
            .unwrap(),
            second
        );
        assert!(verifier.check_eof().is_ok());
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
                {
                    let seed = transcript.verifier_message::<[u8; 32]>();
                    transcript.verifier_message_pow::<u64>(Blake3PoW::new(seed, BITS))
                }
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
            {
                let seed = direct.verifier_message::<[u8; 32]>();
                direct.verifier_message_pow::<u64>(Blake3PoW::new(seed, BITS))
            }
            .unwrap(),
            challenge
        );
        assert_eq!(direct.into_narg_string(), proof);
        let mut direct = verifier(&proof);
        assert_eq!(
            {
                let seed = direct.verifier_message::<[u8; 32]>();
                direct.verifier_message_pow::<u64>(Blake3PoW::new(seed, BITS))
            }
            .unwrap(),
            challenge
        );
        assert!(direct.check_eof().is_ok());
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn prepared_pow_preserves_explicit_seed_nonce_challenge_sequence() {
        use crate::blake3::Blake3PoW;

        let mut manual = prover();
        let challenge = manual.verifier_message::<[u8; 32]>();
        let solution = PoWGrinder::new(Blake3PoW::new(challenge, BITS))
            .grind()
            .unwrap();
        manual.prover_message(&solution);
        let expected = manual.verifier_message::<u64>();

        let mut bundled = prover();
        assert_eq!(
            {
                let seed = bundled.verifier_message::<[u8; 32]>();
                bundled.verifier_message_pow::<u64>(Blake3PoW::new(seed, BITS))
            }
            .unwrap(),
            expected
        );
        assert_eq!(bundled.into_narg_string(), solution.to_le_bytes());
        assert_eq!(manual.into_narg_string(), solution.to_le_bytes());
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn rejects_a_nonce_that_only_meets_the_lower_difficulty() {
        use crate::blake3::Blake3PoW;

        let challenge = verifier(&[]).verifier_message::<[u8; 32]>();
        let mut easy = PoWGrinder::new(Blake3PoW::new(challenge, BITS));
        let mut hard = PoWGrinder::new(Blake3PoW::new(challenge, BITS + 8));
        // Explicitly choose a nonce that fails the harder predicate; a valid
        // low-difficulty nonce can also satisfy a higher difficulty.
        let nonce = (0..=u64::MAX)
            .find(|&n| easy.verify(n) && !hard.verify(n))
            .unwrap();
        let proof = nonce.to_le_bytes();
        let mut easy_verifier = verifier(&proof);
        assert!({
            let seed = easy_verifier.verifier_message::<[u8; 32]>();
            easy_verifier.verifier_message_pow::<u64>(Blake3PoW::new(seed, BITS))
        }
        .is_ok());
        assert!(easy_verifier.check_eof().is_ok());

        let mut hard_verifier = verifier(&proof);
        assert!({
            let seed = hard_verifier.verifier_message::<[u8; 32]>();
            hard_verifier.verifier_message_pow::<u64>(Blake3PoW::new(seed, BITS + 8))
        }
        .is_err());
        assert!(hard_verifier.prover_messages_vec::<u8>(0).is_err());
        assert!(hard_verifier.check_eof().is_err());
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Event {
        Absorb(Vec<u8>),
        Squeeze(usize),
    }

    thread_local! {
        static EVENTS: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
    }

    fn events() -> Vec<Event> {
        EVENTS.with_borrow(Clone::clone)
    }

    #[derive(Clone)]
    struct RecordingSponge;

    impl DuplexSpongeInterface for RecordingSponge {
        type U = u8;

        fn absorb(&mut self, input: &[u8]) -> &mut Self {
            EVENTS.with_borrow_mut(|events| events.push(Event::Absorb(input.to_vec())));
            self
        }

        fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
            EVENTS.with_borrow_mut(|events| events.push(Event::Squeeze(output.len())));
            output.fill(0);
            self
        }
    }

    impl DuplexSpongeInit for RecordingSponge {
        fn init(_session_id: &[u8; 32]) -> Self {
            Self
        }
    }

    /// A verifier over [`RecordingSponge`], with the log cleared after the
    /// instance is absorbed.
    fn recording_verifier(proof: &[u8]) -> VerifierState<'_, RecordingSponge> {
        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        let verifier = VerifierState::new(&session_id, &0u32, proof);
        EVENTS.with_borrow_mut(Vec::clear);
        verifier
    }

    #[derive(Clone)]
    struct FixedPredicate<const ACCEPT: bool>;

    impl<const ACCEPT: bool> PowStrategy for FixedPredicate<ACCEPT> {
        fn check(&mut self, _nonce: u64) -> bool {
            ACCEPT
        }

        fn solve(&mut self) -> Option<u64> {
            assert!(!ACCEPT, "verifier must not run the nonce search");
            None
        }
    }

    #[test]
    fn exhausted_grinding_returns_an_error_without_sending_a_nonce() {
        let mut prover = prover();
        assert!(prover
            .verifier_message_pow::<u64>(FixedPredicate::<false>)
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
                let _ = transcript.verifier_message_pow::<u64>(FixedPredicate::<false>);
                Ok(())
            }
        }
        assert!(Narg::verify::<SwallowsFailure>(b"caught PoW failure", &0, &[0; 8]).is_err());
    }

    #[test]
    fn rejected_nonce_blocks_challenge_and_poisoning_persists() {
        #[derive(Clone)]
        struct BoundedPredicate;

        impl PowStrategy for BoundedPredicate {
            fn check(&mut self, _nonce: u64) -> bool {
                true
            }

            fn last_nonce(&self) -> u64 {
                0
            }
        }

        fn assert_rejected(strategy: impl PowStrategy, nonce: u64) {
            let proof = nonce.to_le_bytes();
            let mut verifier = recording_verifier(&proof);
            assert!(verifier
                .verifier_message_pow::<u64>(strategy.clone())
                .is_err());
            // The nonce is an ordinary prover message. Its failed check prevents
            // the protected challenge, even though all proof bytes were consumed.
            assert_eq!(events(), [Event::Absorb(proof.to_vec())]);
            assert!(verifier
                .check(|| panic!("a failed check must not run again"))
                .is_err());
            assert!(verifier.prover_message::<u8>().is_err());
            assert!(verifier.prover_messages_vec::<u8>(0).is_err());
            assert!(verifier.verifier_message_pow::<u64>(strategy).is_err());
            assert!(verifier.check_eof().is_err());
        }

        assert_rejected(FixedPredicate::<false>, 0);
        assert_rejected(BoundedPredicate, 1);
    }

    #[test]
    fn valid_nonce_is_absorbed_before_the_protected_challenge() {
        let proof = 42u64.to_le_bytes();
        let mut verifier = recording_verifier(&proof);
        assert_eq!(
            verifier
                .verifier_message_pow::<u64>(FixedPredicate::<true>)
                .unwrap(),
            0
        );
        assert_eq!(events(), [Event::Absorb(proof.to_vec()), Event::Squeeze(8)]);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn every_truncated_nonce_is_rejected() {
        for length in 0..8 {
            let proof = vec![0; length];
            let mut verifier = recording_verifier(&proof);
            // Even an always-accepting predicate cannot rescue a short nonce.
            assert!(verifier
                .verifier_message_pow::<u64>(FixedPredicate::<true>)
                .is_err());
            assert_eq!(events(), []);
            assert!(verifier.check_eof().is_err());
        }
    }
}
