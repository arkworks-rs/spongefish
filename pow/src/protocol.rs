//! An interactive proof-of-work step shared by every transcript implementation.

use spongefish::{FromUniform, Transcript, VerificationError};

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
/// The PoW strategy, difficulty, position of this step, and the codec of the
/// protected message must be fixed by the protocol and accounted for in its
/// session tag. The difficulty must not come from an untrusted proof value.
/// Any soundness benefit depends on the surrounding protocol and PoW strategy.
///
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
        T: FromUniform,
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
    use std::cell::RefCell;

    use spongefish::{
        instantiations::{Shake128, TurboShake128},
        Argument, DuplexSpongeInit, DuplexSpongeInterface, Narg, ProverState, Transcript,
        VerificationError, VerifierState, Witness,
    };

    use super::PowTranscriptExt;
    use crate::{PoWSolution, PowStrategy};

    // Use different public/private sponges to exercise the refactored RNG bound.
    fn prover() -> ProverState<TurboShake128, Shake128> {
        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        ProverState::new_with_seed(&session_id, &0u32, [7; 32])
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
        let mut verifier = recording_verifier(&[0; 8]);
        assert!(verifier
            .verifier_message_pow::<u64, FixedPredicate<false>>(8.0)
            .is_err());
        // The nonce is an ordinary prover message. Its failed check prevents
        // the protected challenge, even though all proof bytes were consumed.
        assert_eq!(events(), [Event::Squeeze(32), Event::Absorb(vec![0; 8])]);
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
        let proof = 42u64.to_le_bytes();
        let mut verifier = recording_verifier(&proof);
        assert_eq!(
            verifier
                .verifier_message_pow::<u64, FixedPredicate<true>>(8.0)
                .unwrap(),
            0
        );
        assert_eq!(
            events(),
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
            let proof = vec![0; length];
            let mut verifier = recording_verifier(&proof);
            // Even an always-accepting predicate cannot rescue a short nonce.
            assert!(verifier
                .verifier_message_pow::<u64, FixedPredicate<true>>(8.0)
                .is_err());
            assert_eq!(events(), [Event::Squeeze(32)]);
            assert!(verifier.check_eof().is_err());
        }
    }
}
