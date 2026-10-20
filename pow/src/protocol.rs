//! An interactive proof-of-work step shared by every transcript implementation.

use spongefish::{FromUniform, Probe, Transcript, VerificationError};

use crate::{PoWGrinder, PowStrategy};

/// Proof-of-work-protected verifier messages for interactive transcripts.
///
/// This extension is available on every [`Transcript`], including concrete
/// [`ProverState`](spongefish::ProverState) and
/// [`VerifierState`](spongefish::VerifierState) values and the generic transcript
/// passed to [`Argument::run`](spongefish::Argument::run).
///
/// There are two variants. [`verifier_message_pow`](Self::verifier_message_pow)
/// obtains a 32-byte grinding challenge, exchanges a little-endian `u64` nonce,
/// checks it with a [`PowStrategy`], then obtains the protected verifier
/// message. [`verifier_message_sponge_pow`](Self::verifier_message_sponge_pow)
/// exchanges a nonce sized to the difficulty and checks it against bytes
/// squeezed from the transcript sponge itself. In both, grinding is a
/// prover-only computation; the verifier checks the received nonce without
/// running the search.
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

    /// Obtain a verifier message after a proof of work on the transcript
    /// sponge itself.
    ///
    /// For `bits > 0`, the prover sends a nonce of `ceil((bits + 7) / 8)`
    /// little-endian bytes. Both parties then squeeze `ceil(bits / 8)` bytes and
    /// accept the nonce iff their low `bits` bits are zero. The protected
    /// verifier message is squeezed next, from the bytes that follow. For
    /// `bits == 0`, no nonce is sent and this is
    /// [`Transcript::verifier_message`].
    ///
    /// The nonce space is at least `2^7` times the expected number of trials,
    /// so for an ideal sponge an honest search fails with probability at most
    /// about `e^-128`. The prover searches with [`Transcript::prover_search`].
    ///
    /// # Security
    ///
    /// For a fresh ideal transcript-output sample, the check passes with
    /// probability `2^-bits`, and conditioning only on that check leaves the
    /// remaining bytes uniform. A cheating prover can also select on the
    /// protected message, paying for both conditions. The soundness of the
    /// whole protocol depends on its state-restoration soundness, on the
    /// backend's reduction to an ideal primitive, and on the decoding bias of
    /// `T`. Chiesa and Orrù give such a reduction, with an additive error, for
    /// the permutation-backed overwrite duplex sponge; it does not by itself
    /// cover the digest and XOF bridges. The difficulty, the position of this
    /// step, the backend and the codec of `T` must be fixed by the protocol and
    /// bound in its session.
    ///
    /// # Cost
    ///
    /// This step needs no separate proof-of-work hash and no grinding
    /// challenge. With a permutation-backed sponge, when the nonce fits in the
    /// current absorb block and the check and `T` fit in one rate block, each
    /// search trial costs one permutation call and the verifier needs one
    /// permutation after the nonce. Other alignments, longer outputs and other
    /// backends can cost more.
    ///
    /// # Errors
    ///
    /// The prover returns [`VerificationError`] if the search exhausts the
    /// nonce space, or if the transcript does not support
    /// [`Transcript::prover_search`] and rejects the resulting unknown prover
    /// message, as [`ProverState`](spongefish::ProverState) does. For
    /// `bits > 0`, the verifier returns it if the nonce is invalid, the proof
    /// is truncated, or an earlier read or check rejected the transcript.
    ///
    /// # Panics
    ///
    /// Panics if `bits > 57`. Above that, an 8-byte nonce no longer leaves
    /// `2^7` times the expected work.
    fn verifier_message_sponge_pow<T>(&mut self, bits: u32) -> Result<T, VerificationError>
    where
        T: FromUniform,
    {
        let pow = SpongePow::new(bits);
        if bits == 0 {
            return Ok(self.verifier_message());
        }
        let nonce = self
            .prover_search(|probe| pow.search(probe))
            .map(|nonce| nonce.ok_or(VerificationError))
            .transpose()?;
        for i in 0..pow.nonce_len() {
            self.prover_message(nonce.as_ref().map(|nonce| nonce[i]))?;
        }
        let mut word = [0u8; 8];
        for byte in &mut word[..pow.word_len()] {
            *byte = self.verifier_message();
        }
        self.check(|| pow.accepts(word))?;
        Ok(self.verifier_message())
    }
}

impl<T: Transcript + ?Sized> PowTranscriptExt for T {}

/// The layout of [`PowTranscriptExt::verifier_message_sponge_pow`] at a
/// difficulty of `bits`.
#[derive(Clone, Copy)]
struct SpongePow {
    bits: u32,
}

impl SpongePow {
    /// The largest difficulty whose nonce, at most 8 bytes, still leaves
    /// `2^7` times the expected work.
    const MAX_BITS: u32 = 57;

    fn new(bits: u32) -> Self {
        assert!(bits <= Self::MAX_BITS, "bits must be at most 57");
        Self { bits }
    }

    /// `ceil((bits + 7) / 8)` nonce bytes, at most 8 since `bits <= 57`.
    const fn nonce_len(self) -> usize {
        (self.bits as usize + 14) / 8
    }

    /// `ceil(bits / 8)` squeezed bytes carry the checked bits.
    const fn word_len(self) -> usize {
        (self.bits as usize).div_ceil(8)
    }

    /// The low `bits` bits of the little-endian word are zero.
    const fn accepts(self, word: [u8; 8]) -> bool {
        u64::from_le_bytes(word) & ((1u64 << self.bits) - 1) == 0
    }

    /// The largest nonce that fits in `nonce_len` bytes.
    const fn last_nonce(self) -> u64 {
        u64::MAX >> (64 - 8 * self.nonce_len())
    }

    /// Whether sending `nonce` makes the next squeezed bytes pass the check.
    fn accepts_nonce(self, probe: &dyn Probe, nonce: u64) -> bool {
        let mut word = [0u8; 8];
        probe.probe(
            &nonce.to_le_bytes()[..self.nonce_len()],
            &mut word[..self.word_len()],
        );
        self.accepts(word)
    }

    /// The least accepted nonce, as little-endian bytes.
    #[cfg(not(feature = "parallel"))]
    fn search(self, probe: &dyn Probe) -> Option<[u8; 8]> {
        (0..=self.last_nonce())
            .find(|&nonce| self.accepts_nonce(probe, nonce))
            .map(u64::to_le_bytes)
    }

    /// The least accepted nonce, as little-endian bytes, searched on all
    /// threads. The result equals the sequential search.
    #[cfg(feature = "parallel")]
    fn search(self, probe: &dyn Probe) -> Option<[u8; 8]> {
        use std::sync::atomic::{AtomicU64, Ordering};

        let last = self.last_nonce();
        let least = AtomicU64::new(u64::MAX);
        rayon::broadcast(|ctx| {
            // Each thread scans its own residue class in increasing order and
            // stops once it cannot beat the least nonce found so far.
            let nonces = (ctx.index() as u64..=last).step_by(ctx.num_threads());
            for nonce in nonces {
                if nonce >= least.load(Ordering::Relaxed) {
                    break;
                }
                if self.accepts_nonce(probe, nonce) {
                    least.fetch_min(nonce, Ordering::SeqCst);
                    break;
                }
            }
        });
        // `u64::MAX` is also the "not found" value. Workers never probe it, so
        // check it here when the nonce space reaches it.
        match least.load(Ordering::SeqCst) {
            u64::MAX => (last == u64::MAX && self.accepts_nonce(probe, u64::MAX))
                .then(|| u64::MAX.to_le_bytes()),
            nonce => Some(nonce.to_le_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use spongefish::{
        instantiations::{Shake128, TurboShake128},
        Argument, DuplexSpongeInit, DuplexSpongeInterface, MessageSearch, Narg, Probe, ProverState,
        Transcript, VerificationError, VerifierState, Witness,
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

    /// Bits 0..8 of the next squeezed byte after sending `nonce` are zero.
    fn meets_eight_bits(search: &MessageSearch<TurboShake128>, nonce: [u8; 2]) -> bool {
        let mut word = [0u8; 1];
        search.probe(&nonce, &mut word);
        word[0] == 0
    }

    #[test]
    fn sponge_pow_round_trip_sends_a_nonce_sized_to_the_difficulty() {
        let mut prover = prover();
        prover.prover_message(&123u32);
        let first: u64 = prover.verifier_message_sponge_pow(8).unwrap();
        let second: [u8; 32] = prover.verifier_message_sponge_pow(12).unwrap();
        let third: u64 = prover.verifier_message_sponge_pow(0).unwrap();
        let proof = prover.into_narg_string();
        // 8 bits use a 2-byte nonce, 12 bits a 3-byte nonce, 0 bits none.
        assert_eq!(proof.len(), 4 + 2 + 3);

        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        let mut verifier = VerifierState::<TurboShake128>::new(&session_id, &0u32, &proof);
        assert_eq!(verifier.prover_message::<u32>().unwrap(), 123);
        assert_eq!(
            verifier.verifier_message_sponge_pow::<u64>(8).unwrap(),
            first
        );
        assert_eq!(
            verifier
                .verifier_message_sponge_pow::<[u8; 32]>(12)
                .unwrap(),
            second
        );
        assert_eq!(
            verifier.verifier_message_sponge_pow::<u64>(0).unwrap(),
            third
        );
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn sponge_pow_matches_the_manual_transcript() {
        let mut manual = prover();
        let search = manual.message_search();
        let nonce = (0..=u16::MAX)
            .map(u16::to_le_bytes)
            .find(|&nonce| meets_eight_bits(&search, nonce))
            .unwrap();
        manual.prover_message(&nonce[0]);
        manual.prover_message(&nonce[1]);
        assert_eq!(manual.verifier_message::<u8>(), 0);
        let expected: u64 = manual.verifier_message();

        let mut fused = prover();
        assert_eq!(
            fused.verifier_message_sponge_pow::<u64>(8).unwrap(),
            expected
        );
        assert_eq!(fused.into_narg_string(), nonce);
        assert_eq!(manual.into_narg_string(), nonce);
    }

    #[test]
    fn sponge_pow_argument_and_direct_state_apis_agree() {
        struct SpongePowRound;
        impl Argument for SpongePowRound {
            type Instance = u32;
            type Witness = ();
            type Output = u64;

            fn run<T: Transcript>(
                transcript: &mut T,
                _instance: &u32,
                _witness: Witness<&()>,
            ) -> Result<u64, VerificationError> {
                transcript.verifier_message_sponge_pow(10)
            }
        }

        let tag = b"pow/tests/v1";
        let (proof, challenge) = Narg::prove::<SpongePowRound>(tag, &0, &()).unwrap();
        assert_eq!(proof.len(), 3);
        assert_eq!(
            Narg::verify::<SpongePowRound>(tag, &0, &proof).unwrap(),
            challenge
        );

        let mut direct = prover();
        assert_eq!(
            direct.verifier_message_sponge_pow::<u64>(10).unwrap(),
            challenge
        );
        assert_eq!(direct.into_narg_string(), proof);
    }

    #[test]
    fn sponge_pow_rejects_a_nonce_that_misses_the_target() {
        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        // The prover and verifier sponges agree before the nonce.
        let search = prover().message_search();
        let nonces = || (0..=u16::MAX).map(u16::to_le_bytes);
        let good = nonces().find(|&n| meets_eight_bits(&search, n)).unwrap();
        let bad = nonces().find(|&n| !meets_eight_bits(&search, n)).unwrap();

        let mut verifier = VerifierState::<TurboShake128>::new(&session_id, &0u32, &good);
        assert!(verifier.verifier_message_sponge_pow::<u64>(8).is_ok());
        assert!(verifier.check_eof().is_ok());

        let mut verifier = VerifierState::<TurboShake128>::new(&session_id, &0u32, &bad);
        assert!(verifier.verifier_message_sponge_pow::<u64>(8).is_err());
        assert!(verifier.prover_message::<u8>().is_err());
        assert!(verifier.check_eof().is_err());

        for length in 0..2 {
            let proof = &good[..length];
            let mut verifier = VerifierState::<TurboShake128>::new(&session_id, &0u32, proof);
            assert!(verifier.verifier_message_sponge_pow::<u64>(8).is_err());
            assert!(verifier.check_eof().is_err());
        }
    }

    #[test]
    fn sponge_pow_verifier_absorbs_the_nonce_then_squeezes_check_and_challenge() {
        // The recording sponge squeezes zeros, so every nonce meets the target.
        let proof = [42, 0, 7];
        let mut verifier = recording_verifier(&proof);
        assert_eq!(verifier.verifier_message_sponge_pow::<u64>(10).unwrap(), 0);
        assert_eq!(
            events(),
            [
                Event::Absorb(vec![42]),
                Event::Absorb(vec![0]),
                Event::Absorb(vec![7]),
                Event::Squeeze(1),
                Event::Squeeze(1),
                Event::Squeeze(8)
            ]
        );
        assert!(verifier.check_eof().is_ok());

        let mut verifier = recording_verifier(&[]);
        assert_eq!(verifier.verifier_message_sponge_pow::<u64>(0).unwrap(), 0);
        assert_eq!(events(), [Event::Squeeze(8)]);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn sponge_pow_layout() {
        use super::SpongePow;
        let layout = |bits| {
            let pow = SpongePow::new(bits);
            (pow.nonce_len(), pow.word_len())
        };
        assert_eq!(layout(1), (1, 1));
        assert_eq!(layout(8), (2, 1));
        assert_eq!(layout(10), (3, 2));
        assert_eq!(layout(49), (7, 7));
        assert_eq!(layout(50), (8, 7));
        assert_eq!(layout(57), (8, 8));
        let pow = SpongePow::new(10);
        assert!(pow.accepts([0, 0b1111_1100, 0xff, 0, 0, 0, 0, 0]));
        assert!(!pow.accepts([0, 0b0000_0010, 0, 0, 0, 0, 0, 0]));
        assert!(!pow.accepts([1, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn sponge_pow_search_returns_the_least_nonce() {
        use super::SpongePow;
        let search = prover().message_search();
        for bits in [1, 5, 12] {
            let pow = SpongePow::new(bits);
            let least = (0..=pow.last_nonce())
                .find(|&nonce| pow.accepts_nonce(&search, nonce))
                .map(u64::to_le_bytes);
            assert!(least.is_some());
            assert_eq!(pow.search(&search), least);
        }
    }

    /// Accepts exactly one nonce, or none.
    struct AcceptOnly(Option<u64>);

    impl Probe for AcceptOnly {
        fn probe(&self, candidate: &[u8], out: &mut [u8]) {
            let mut nonce = [0u8; 8];
            nonce[..candidate.len()].copy_from_slice(candidate);
            let hit = self.0 == Some(u64::from_le_bytes(nonce));
            out.fill(if hit { 0 } else { 0xff });
        }
    }

    #[test]
    fn sponge_pow_search_finds_a_lone_nonce_anywhere_in_the_space() {
        use super::SpongePow;
        for bits in [1, 9] {
            let pow = SpongePow::new(bits);
            let last = pow.last_nonce();
            for target in [None, Some(0), Some(1), Some(last / 2), Some(last)] {
                let expected = target.map(u64::to_le_bytes);
                assert_eq!(pow.search(&AcceptOnly(target)), expected);
                #[cfg(feature = "parallel")]
                {
                    let one_thread = rayon::ThreadPoolBuilder::new()
                        .num_threads(1)
                        .build()
                        .unwrap();
                    assert_eq!(
                        one_thread.install(|| pow.search(&AcceptOnly(target))),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "bits must be at most 57")]
    fn sponge_pow_rejects_unsupported_difficulty() {
        let _ = prover().verifier_message_sponge_pow::<u64>(58);
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
