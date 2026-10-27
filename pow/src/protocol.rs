//! Proof of work on the transcript sponge.
//!
//! The prover grinds a nonce so that, once it is absorbed, the low `bits` bits
//! of the next squeezed bytes (read little-endian) are zero. Both parties check
//! those bits and then squeeze the protected verifier message. The work is
//! bound to that message: a proof-of-work check detached from the next
//! challenge does not amplify soundness.

#[cfg(feature = "parallel")]
use spongefish::{DuplexSpongeInit, DuplexSpongeInterface, ProverState};
use spongefish::{FromUniform, Transcript, VerificationError, Witness};

use crate::{PoWGrinder, PowStrategy};

/// Adds [`verifier_message_pow`](Self::verifier_message_pow) to every
/// [`Transcript`], including [`ProverState`](spongefish::ProverState),
/// [`VerifierState`](spongefish::VerifierState) and the transcript passed to
/// [`Argument::run`](spongefish::Argument::run).
///
/// # Example
///
/// ```
/// use spongefish::{Argument, Narg, Transcript, VerificationError, Witness};
/// use spongefish_pow::PowTranscriptExt;
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
///         transcript.verifier_message_pow(8)
///     }
/// }
///
/// let tag = b"example/v1/sponge-pow-8/u32";
/// let (proof, challenge) = Narg::prove::<PowRound>(tag, &0, &())?;
/// let replay = Narg::verify::<PowRound>(tag, &0, &proof)?;
/// assert_eq!(challenge, replay);
/// # Ok::<(), spongefish::VerificationError>(())
/// ```
pub trait PowTranscriptExt: Transcript {
    /// Grind `bits` bits of work into the transcript, then return a verifier message.
    ///
    /// For `bits > 0`:
    ///
    /// 1. The prover sends the least nonce `n <= 2^(bits+7) - 1` that passes
    ///    the check, as canonical LEB128: seven bits per byte, least
    ///    significant first, no redundant trailing byte.
    /// 2. Both parties squeeze `ceil(bits / 8)` bytes and accept iff their low
    ///    `bits` bits, read little-endian, are zero.
    /// 3. Both parties return [`Transcript::verifier_message`].
    ///
    /// For `bits == 0`, no nonce is sent and nothing is squeezed before the
    /// returned message.
    ///
    /// The nonce takes at most `ceil((bits + 7) / 7)` bytes, and one byte with
    /// probability at least `1 - e^-8` when `bits <= 4`. The nonce space holds
    /// `2^7` times the expected search, so for an ideal sponge an honest search
    /// fails with probability at most `e^-128`. Any nonce that passes is
    /// accepted, not only the least, so proofs are not unique.
    ///
    /// # Security
    ///
    /// The returned message, and further verifier messages up to the next
    /// prover message, are protected: each attempt to change them costs a
    /// cheating prover `2^bits` expected trials. The overall bound also depends
    /// on the protocol's state-restoration soundness and on the sponge's
    /// reduction to an ideal permutation; [[CO25]] gives one for the
    /// permutation-backed overwrite duplex sponge. The difficulty, the position
    /// of this step and the type `T` must be fixed by the protocol and bound in
    /// its session tag; `bits` must never come from the proof.
    ///
    /// # Performance
    ///
    /// The search runs sequentially on the calling thread. On a
    /// [`ProverState`](spongefish::ProverState) whose public sponge is `Send`,
    /// `verifier_message_pow_parallel` (feature `parallel`) searches on the
    /// Rayon pool and writes the same proof. With a permutation-backed sponge,
    /// when the nonce, the check bytes and the returned message fit in one rate
    /// block, a search trial costs about one permutation.
    ///
    /// # Errors
    ///
    /// The prover returns [`VerificationError`] if:
    /// - the search exhausts the nonce space;
    /// - the transcript does not provide [`Transcript::verifier_message_oracle`];
    /// - replaying the check on its own transcript rejects the nonce. This means
    ///   the sponge breaks the associativity that
    ///   [`DuplexSpongeInterface`](spongefish::DuplexSpongeInterface) requires.
    ///   The nonce is already written by then, so discard the prover state.
    ///
    /// The verifier returns it if the nonce is truncated, not canonical or above
    /// `2^(bits+7) - 1`, if the check bits are not zero, or if an earlier read
    /// or check already rejected the transcript.
    ///
    /// # Panics
    ///
    /// Panics if `bits > 57`: the `u64` nonce space must hold `2^(bits+7)` values.
    ///
    /// [CO25]: https://eprint.iacr.org/2025/536.pdf
    fn verifier_message_pow<T: FromUniform>(&mut self, bits: u32) -> Result<T, VerificationError> {
        validate_bits(bits);
        let nonce = if bits == 0 {
            Witness::unknown()
        } else {
            self.verifier_message_oracle()
                .map(|evaluate| PoWGrinder::new(TranscriptPoW::new(evaluate, bits)).grind())
        };
        finish_pow(self, bits, nonce)
    }
}

impl<T: Transcript + ?Sized> PowTranscriptExt for T {}

/// Like [`PowTranscriptExt::verifier_message_pow`], but searches on the Rayon pool.
///
/// Requires the `parallel` feature and a `Send` public sponge; the private RNG
/// needs neither `Send` nor `Sync`. It writes the same proof, so the verifier
/// uses the sequential method.
///
/// ```
/// use spongefish::{DefaultHash, Narg, ProverState, VerifierState};
/// use spongefish_pow::{verifier_message_pow_parallel, PowTranscriptExt};
///
/// let session = Narg::derive_session_id(b"parallel-pow/v1");
/// let mut prover = ProverState::<DefaultHash>::new(&session, &0u32);
/// let challenge = verifier_message_pow_parallel::<u64>(&mut prover, 8)?;
/// let proof = prover.into_narg_string();
/// let mut verifier = VerifierState::<DefaultHash>::new(&session, &0u32, &proof);
/// assert_eq!(verifier.verifier_message_pow::<u64>(8)?, challenge);
/// verifier.check_eof()?;
/// # Ok::<(), spongefish::VerificationError>(())
/// ```
#[cfg(feature = "parallel")]
pub fn verifier_message_pow_parallel<T: FromUniform>(
    prover: &mut ProverState<
        impl DuplexSpongeInterface<U = u8> + Send,
        impl DuplexSpongeInit<U = u8>,
    >,
    bits: u32,
) -> Result<T, VerificationError> {
    validate_bits(bits);
    let nonce = if bits == 0 {
        Witness::unknown()
    } else {
        Witness::known(
            PoWGrinder::new(TranscriptPoW::new(prover.verifier_message_oracle(), bits))
                .grind_parallel(),
        )
    };
    finish_pow(prover, bits, nonce)
}

// Both search paths share every proof-writing and verification operation.
fn finish_pow<T: FromUniform>(
    transcript: &mut (impl Transcript + ?Sized),
    bits: u32,
    nonce: Witness<Option<u64>>,
) -> Result<T, VerificationError> {
    if bits == 0 {
        transcript.check(|| true)?;
        return Ok(transcript.verifier_message());
    }
    let nonce = nonce
        .map(|nonce| nonce.ok_or(VerificationError))
        .transpose()?
        .map(Leb128::new);
    let mut value = 0u128;
    let mut last = 0x80;
    let mut len = 0;
    while last & 0x80 != 0 && len < max_nonce_len(bits) {
        last = transcript.prover_message(nonce.as_ref().map(|nonce| nonce.bytes[len]))?;
        value |= u128::from(last & 0x7f) << (7 * len);
        len += 1;
    }
    transcript.check(|| {
        last & 0x80 == 0 && (len == 1 || last != 0) && value <= u128::from(last_nonce(bits))
    })?;
    let mut word = [0u8; 8];
    for byte in &mut word[..word_len(bits)] {
        *byte = transcript.verifier_message();
    }
    let accepted = accepts(bits, word);
    // `ProverState::check` skips its predicate in release builds. The prover
    // re-checks the replayed word anyway (one comparison), so a duplex sponge
    // whose byte-at-a-time absorb and squeeze disagree with the one-shot search
    // evaluator yields an error instead of a proof the verifier rejects.
    if nonce.map(|_| accepted).into_known() == Some(false) {
        return Err(VerificationError);
    }
    transcript.check(|| accepted)?;
    Ok(transcript.verifier_message())
}

// Reserve 2^7 times the expected work in the u64 nonce space.
const MAX_BITS: u32 = 57;

fn validate_bits(bits: u32) {
    assert!(bits <= MAX_BITS, "bits must be at most 57");
}

const fn last_nonce(bits: u32) -> u64 {
    u64::MAX >> (MAX_BITS - bits)
}

const fn max_nonce_len(bits: u32) -> usize {
    (bits as usize + 13) / 7
}

const fn word_len(bits: u32) -> usize {
    (bits as usize).div_ceil(8)
}

const fn accepts(bits: u32, word: [u8; 8]) -> bool {
    u64::from_le_bytes(word) & ((1u64 << bits) - 1) == 0
}

/// A PoW strategy that tests nonces through the transcript's verifier-message oracle.
#[derive(Clone)]
struct TranscriptPoW<E> {
    evaluate: E,
    bits: u32,
}

impl<E> TranscriptPoW<E> {
    fn new(evaluate: E, bits: u32) -> Self {
        validate_bits(bits);
        Self { evaluate, bits }
    }
}

impl<E: Fn(&[u8], &mut [u8]) + Clone> PowStrategy for TranscriptPoW<E> {
    fn check(&mut self, nonce: u64) -> bool {
        let mut word = [0u8; 8];
        (self.evaluate)(
            Leb128::new(nonce).as_bytes(),
            &mut word[..word_len(self.bits)],
        );
        accepts(self.bits, word)
    }

    fn last_nonce(&self) -> u64 {
        last_nonce(self.bits)
    }
}

/// The canonical LEB128 encoding of a `u64`.
#[derive(Clone, Copy)]
struct Leb128 {
    bytes: [u8; 10],
    len: usize,
}

impl Leb128 {
    const fn new(mut value: u64) -> Self {
        let mut bytes = [0u8; 10];
        let mut len = 0;
        loop {
            let low = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                bytes[len] = low;
                return Self {
                    bytes,
                    len: len + 1,
                };
            }
            bytes[len] = low | 0x80;
            len += 1;
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use spongefish::{
        instantiations::{Shake128, TurboShake128},
        Argument, DuplexSpongeInit, DuplexSpongeInterface, Narg, ProverState, Transcript,
        VerificationError, VerifierState, Witness,
    };

    use super::PowTranscriptExt;
    // Different public and private sponge types catch a bound placed on the wrong one.
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
    struct RecordingSponge<const OUTPUT: u8 = 0>;

    impl<const OUTPUT: u8> DuplexSpongeInterface for RecordingSponge<OUTPUT> {
        type U = u8;

        fn absorb(&mut self, input: &[u8]) -> &mut Self {
            EVENTS.with_borrow_mut(|events| events.push(Event::Absorb(input.to_vec())));
            self
        }

        fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
            EVENTS.with_borrow_mut(|events| events.push(Event::Squeeze(output.len())));
            output.fill(OUTPUT);
            self
        }
    }

    impl<const OUTPUT: u8> DuplexSpongeInit for RecordingSponge<OUTPUT> {
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

    #[test]
    fn exhausted_grinding_returns_an_error_without_sending_a_nonce() {
        let session_id = Narg::derive_session_id(b"pow/tests/exhausted");
        let mut prover =
            ProverState::<RecordingSponge<255>>::new_with_seed(&session_id, &0u32, [7; 32]);
        assert!(prover.verifier_message_pow::<u64>(1).is_err());
        assert_eq!(prover.into_narg_string(), b"");
        #[cfg(feature = "parallel")]
        {
            let mut parallel =
                ProverState::<RecordingSponge<255>>::new_with_seed(&session_id, &0u32, [7; 32]);
            assert!(super::verifier_message_pow_parallel::<u64>(&mut parallel, 1).is_err());
            assert_eq!(parallel.into_narg_string(), b"");
        }
    }

    #[test]
    fn prover_rejects_a_nonce_its_own_replay_rejects() {
        // Squeezes of one byte return 0xff, longer squeezes return zeros. The
        // one-shot search evaluator squeezes the whole check word and accepts
        // the first nonce; the byte-at-a-time replay rejects it. This violates
        // the associativity that `DuplexSpongeInterface` requires.
        #[derive(Clone)]
        struct NonAssociativeSponge;

        impl DuplexSpongeInterface for NonAssociativeSponge {
            type U = u8;

            fn absorb(&mut self, _input: &[u8]) -> &mut Self {
                self
            }

            fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
                output.fill(if output.len() == 1 { 0xff } else { 0 });
                self
            }
        }

        impl DuplexSpongeInit for NonAssociativeSponge {
            fn init(_session_id: &[u8; 32]) -> Self {
                Self
            }
        }

        let session_id = Narg::derive_session_id(b"pow/tests/non-associative");
        let mut prover =
            ProverState::<NonAssociativeSponge>::new_with_seed(&session_id, &0u32, [7; 32]);
        // 9 bits use a two-byte check word.
        assert!(prover.verifier_message_pow::<u64>(9).is_err());
        // The nonce is written before the replay rejects it.
        assert_eq!(prover.narg_string(), [0u8]);
        #[cfg(feature = "parallel")]
        {
            let mut parallel =
                ProverState::<NonAssociativeSponge>::new_with_seed(&session_id, &0u32, [7; 32]);
            assert!(super::verifier_message_pow_parallel::<u64>(&mut parallel, 9).is_err());
        }
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
                let _ = transcript.verifier_message_pow::<u64>(8);
                Ok(())
            }
        }
        // Non-canonical nonce: an unnecessary trailing zero byte.
        assert!(Narg::verify::<SwallowsFailure>(b"caught PoW failure", &0, &[0x80, 0]).is_err());
    }

    #[test]
    fn rejected_nonce_blocks_challenge_and_poisoning_persists() {
        let session_id = Narg::derive_session_id(b"pow/tests/rejected");
        let mut verifier = VerifierState::<RecordingSponge<255>>::new(&session_id, &0u32, &[0]);
        EVENTS.with_borrow_mut(Vec::clear);
        assert!(verifier.verifier_message_pow::<u64>(8).is_err());
        // Only the check byte is squeezed; no protected challenge is produced.
        assert_eq!(events(), [Event::Absorb(vec![0]), Event::Squeeze(1)]);
        assert!(verifier.verifier_message_pow::<u64>(0).is_err());
        assert_eq!(events(), [Event::Absorb(vec![0]), Event::Squeeze(1)]);
        assert!(verifier
            .check(|| panic!("a failed check must not run again"))
            .is_err());
        assert!(verifier.prover_message::<u8>().is_err());
        assert!(verifier.prover_messages_vec::<u8>(0).is_err());
        assert!(verifier.verifier_message_pow::<u64>(8).is_err());
        assert!(verifier.check_eof().is_err());
    }

    /// The canonical LEB128 encoding of `nonce`.
    fn leb128(nonce: u64) -> Vec<u8> {
        super::Leb128::new(nonce).as_bytes().to_vec()
    }

    /// Whether a candidate makes the next squeezed byte zero.
    fn meets_eight_bits(evaluate: &impl Fn(&[u8], &mut [u8]), nonce: u64) -> bool {
        let mut word = [0u8; 1];
        evaluate(&leb128(nonce), &mut word);
        word[0] == 0
    }

    fn reference_nonce(mut nonce: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let digit = (nonce % 128) as u8;
            nonce /= 128;
            bytes.push(digit + if nonce == 0 { 0 } else { 128 });
            if nonce == 0 {
                return bytes;
            }
        }
    }

    fn reference_round<H: DuplexSpongeInit<U = u8>>(
        bits: u32,
        padding: usize,
        skipped: usize,
    ) -> (Vec<u8>, u64, u64) {
        let session = Narg::derive_session_id(b"pow/tests/vectors/v1");
        let mut before = H::init(session.as_bytes());
        before.absorb(&0u32.to_le_bytes());
        before.absorb(&vec![42; padding]);
        let (proof, mut after) = if bits == 0 {
            (Vec::new(), before)
        } else {
            (0..1u64 << (bits + 7))
                .find_map(|nonce| {
                    let proof = reference_nonce(nonce);
                    let mut after = before.clone();
                    after.absorb(&proof);
                    let mut check = vec![0; bits.div_ceil(8) as usize];
                    after.squeeze(&mut check);
                    let passes =
                        (0..bits).all(|bit| check[bit as usize / 8] & (1 << (bit % 8)) == 0);
                    passes.then_some((proof, after))
                })
                .unwrap()
        };
        let challenge = u64::from_le_bytes(after.squeeze_array());
        after.squeeze(&mut vec![0; skipped]);
        let following = u64::from_le_bytes(after.squeeze_array());
        (proof, challenge, following)
    }

    #[test]
    fn fixed_protocol_vectors_match_an_independent_manual_reference() {
        // Fixed answers cover zero work, short and longer nonces, a partial
        // check byte, and absorb/output boundaries of the 168-byte XOF rate.
        let vectors: &[Vector] = &[
            (
                0,
                0,
                0,
                &[],
                13_056_027_867_765_232_788,
                12_177_758_299_268_758_940,
            ),
            (
                1,
                0,
                0,
                &[1],
                2_543_273_970_772_696_169,
                2_104_723_910_452_070_239,
            ),
            (
                8,
                0,
                0,
                &[184, 1],
                14_629_531_661_013_474_542,
                8_580_657_427_383_256_097,
            ),
            (
                9,
                164,
                152,
                &[171, 3],
                12_866_269_379_798_860_464,
                9_699_166_822_687_270_203,
            ),
            (
                14,
                0,
                0,
                &[255, 243, 2],
                13_141_951_274_061_256_715,
                1_390_169_760_608_021_913,
            ),
        ];
        for &vector in vectors {
            assert_vector::<TurboShake128>(vector);
        }
    }

    type Vector = (u32, usize, usize, &'static [u8], u64, u64);

    fn assert_vector<H: DuplexSpongeInit<U = u8> + Send>(
        (bits, padding, skipped, proof, challenge, following): Vector,
    ) {
        let session = Narg::derive_session_id(b"pow/tests/vectors/v1");
        let reference = reference_round::<H>(bits, padding, skipped);
        assert_eq!(reference, (proof.to_vec(), challenge, following));
        let mut prover = ProverState::<H, Shake128>::new_with_seed(&session, &0u32, [7; 32]);
        for _ in 0..padding {
            prover.public_message(&42u8);
        }
        assert_eq!(prover.verifier_message_pow::<u64>(bits).unwrap(), challenge);
        for _ in 0..skipped {
            let _ = prover.verifier_message::<u8>();
        }
        assert_eq!(prover.verifier_message::<u64>(), following);
        assert_eq!(prover.into_narg_string(), proof);
        let mut verifier = VerifierState::<H>::new(&session, &0u32, proof);
        for _ in 0..padding {
            verifier.public_message(&42u8);
        }
        assert_eq!(
            verifier.verifier_message_pow::<u64>(bits).unwrap(),
            challenge
        );
        for _ in 0..skipped {
            let _ = verifier.verifier_message::<u8>();
        }
        assert_eq!(verifier.verifier_message::<u64>(), following);
        verifier.check_eof().unwrap();
        #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
        for workers in [1, 3, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                let mut parallel =
                    ProverState::<H, Shake128>::new_with_seed(&session, &0u32, [7; 32]);
                for _ in 0..padding {
                    parallel.public_message(&42u8);
                }
                assert_eq!(
                    super::verifier_message_pow_parallel::<u64>(&mut parallel, bits).unwrap(),
                    challenge
                );
                for _ in 0..skipped {
                    let _ = parallel.verifier_message::<u8>();
                }
                assert_eq!(parallel.verifier_message::<u64>(), following);
                assert_eq!(parallel.into_narg_string(), proof);
            });
        }
    }

    #[test]
    fn permutation_duplex_fixed_vector_matches_manual_reference() {
        // The 136-byte overwrite-duplex rate is crossed on both sides.
        assert_vector::<spongefish::instantiations::Keccak>((
            8,
            132,
            120,
            &[141, 2],
            7_525_674_178_905_457_966,
            13_912_007_349_407_221_541,
        ));
    }

    #[test]
    fn verifier_message_pow_argument_and_direct_state_apis_agree() {
        struct SpongePowRound;
        impl Argument for SpongePowRound {
            type Instance = u32;
            type Witness = ();
            type Output = ([u8; 32], u64, u64);

            fn run<T: Transcript>(
                transcript: &mut T,
                _instance: &u32,
                _witness: Witness<&()>,
            ) -> Result<Self::Output, VerificationError> {
                Ok((
                    transcript.verifier_message_pow(10)?,
                    transcript.verifier_message_pow(9)?,
                    transcript.verifier_message_pow(0)?,
                ))
            }
        }

        let tag = b"pow/tests/v1";
        let (proof, challenge) = Narg::prove::<SpongePowRound>(tag, &0, &()).unwrap();
        assert_eq!(
            Narg::verify::<SpongePowRound>(tag, &0, &proof).unwrap(),
            challenge
        );

        let mut direct = prover();
        assert_eq!(
            (
                direct.verifier_message_pow::<[u8; 32]>(10).unwrap(),
                direct.verifier_message_pow::<u64>(9).unwrap(),
                direct.verifier_message_pow::<u64>(0).unwrap(),
            ),
            challenge
        );
        assert_eq!(direct.into_narg_string(), proof);
    }

    #[test]
    fn fused_pow_supports_non_sync_backends() {
        // RefCell deliberately makes the backend non-Sync.
        #[derive(Clone)]
        struct NonSyncSponge<M = ()>(RefCell<TurboShake128>, core::marker::PhantomData<M>);

        impl<M: Clone> DuplexSpongeInterface for NonSyncSponge<M> {
            type U = u8;

            fn absorb(&mut self, input: &[u8]) -> &mut Self {
                self.0.get_mut().absorb(input);
                self
            }

            fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
                self.0.get_mut().squeeze(output);
                self
            }
        }

        impl<M: Clone> DuplexSpongeInit for NonSyncSponge<M> {
            fn init(session_id: &[u8; 32]) -> Self {
                Self(
                    RefCell::new(TurboShake128::init(session_id)),
                    core::marker::PhantomData,
                )
            }
        }

        let session = Narg::derive_session_id(b"pow/tests/v1");
        let mut prover_with_private_rng =
            ProverState::<TurboShake128, NonSyncSponge>::new_with_seed(&session, &0u32, [7; 32]);
        let challenge = prover_with_private_rng
            .verifier_message_pow::<u64>(8)
            .unwrap();
        let mut reference = prover();
        assert_eq!(reference.verifier_message_pow::<u64>(8).unwrap(), challenge);
        let expected_proof = reference.into_narg_string();
        assert_eq!(prover_with_private_rng.into_narg_string(), expected_proof);

        let mut non_sync_public = ProverState::<
            NonSyncSponge<std::rc::Rc<()>>,
            NonSyncSponge<std::rc::Rc<()>>,
        >::new_with_seed(&session, &0u32, [7; 32]);
        assert_eq!(
            non_sync_public.verifier_message_pow::<u64>(8).unwrap(),
            challenge
        );
        assert_eq!(non_sync_public.into_narg_string(), expected_proof);

        #[cfg(feature = "parallel")]
        {
            // Send but non-Sync public H, and neither Send nor Sync private R.
            let mut parallel =
                ProverState::<NonSyncSponge, NonSyncSponge<std::rc::Rc<()>>>::new_with_seed(
                    &session, &0u32, [7; 32],
                );
            assert_eq!(
                super::verifier_message_pow_parallel::<u64>(&mut parallel, 8).unwrap(),
                challenge
            );
            assert_eq!(parallel.into_narg_string(), expected_proof);
        }
    }

    #[test]
    fn verifier_message_pow_rejects_a_nonce_that_misses_the_target() {
        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        // The prover and verifier sponges agree before the nonce.
        let (good, bad) = Transcript::verifier_message_oracle(&prover())
            .map(|evaluate| {
                let good = (0..=u64::MAX)
                    .find(|&n| meets_eight_bits(&evaluate, n))
                    .unwrap();
                let bad = (0..=u64::MAX)
                    .find(|&n| !meets_eight_bits(&evaluate, n))
                    .unwrap();
                (leb128(good), leb128(bad))
            })
            .into_known()
            .unwrap();

        let mut verifier = VerifierState::<TurboShake128>::new(&session_id, &0u32, &good);
        assert!(verifier.verifier_message_pow::<u64>(8).is_ok());
        assert!(verifier.check_eof().is_ok());

        let mut verifier = VerifierState::<TurboShake128>::new(&session_id, &0u32, &bad);
        assert!(verifier.verifier_message_pow::<u64>(8).is_err());
        assert!(verifier.prover_message::<u8>().is_err());
        assert!(verifier.check_eof().is_err());
    }

    #[test]
    fn verifier_message_pow_accepts_only_canonical_nonces_in_range() {
        // The recording sponge squeezes zeros, so every nonce meets the
        // target and only the encoding decides.
        let accepted: &[(u64, u32, &[u8])] = &[
            (0, 1, &[0]),
            (127, 1, &[0x7f]),
            (128, 1, &[0x80, 1]),
            (255, 1, &[0xff, 1]),
            (16383, 7, &[0xff, 0x7f]),
            (16384, 8, &[0x80, 0x80, 1]),
            (u64::from(u32::MAX), 25, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
            (1u64 << 32, 26, &[0x80, 0x80, 0x80, 0x80, 0x10]),
            (
                (1u64 << 63) - 1,
                56,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
            ),
            (
                1u64 << 63,
                57,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 1],
            ),
            (
                u64::MAX,
                57,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1],
            ),
        ];
        for &(nonce, bits, proof) in accepted {
            assert_eq!(leb128(nonce), proof);
            let mut verifier = recording_verifier(proof);
            assert!(
                verifier.verifier_message_pow::<u64>(bits).is_ok(),
                "{proof:?}"
            );
            assert!(verifier.check_eof().is_ok());
        }
        // A trailing zero byte, a nonce of 2^8 at 1 bit, a continuation past
        // the longest encoding, 2^32 at 25 bits, and an overflowing u64 nonce.
        let rejected: &[(u32, &[u8])] = &[
            (1, &[0x80, 0x00]),
            (8, &[0x81, 0x80, 0x00]),
            (1, &[0x80, 0x02]),
            (1, &[0x80, 0x80, 0x01]),
            (25, &[0x80, 0x80, 0x80, 0x80, 0x10]),
            (
                56,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 1],
            ),
            (57, &[0x80; 10]),
            (57, &[0xff; 10]),
            (
                57,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02],
            ),
        ];
        for &(bits, proof) in rejected {
            let mut verifier = recording_verifier(proof);
            assert!(
                verifier.verifier_message_pow::<u64>(bits).is_err(),
                "{proof:?}"
            );
            assert!(verifier.check_eof().is_err());
        }
    }

    #[test]
    fn verifier_message_pow_verifier_absorbs_the_nonce_then_squeezes_the_check() {
        let mut verifier = recording_verifier(&[0x85, 0x01]);
        assert_eq!(verifier.verifier_message_pow::<u64>(10).unwrap(), 0);
        assert_eq!(
            events(),
            [
                Event::Absorb(vec![0x85]),
                Event::Absorb(vec![0x01]),
                Event::Squeeze(1),
                Event::Squeeze(1),
                Event::Squeeze(8)
            ]
        );
        assert!(verifier.check_eof().is_ok());

        let mut verifier = recording_verifier(&[]);
        assert_eq!(verifier.verifier_message_pow::<u64>(0).unwrap(), 0);
        assert_eq!(events(), [Event::Squeeze(8)]);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn permutation_cost_depends_on_absorb_and_squeeze_boundaries() {
        use std::cell::Cell;

        use spongefish::{DuplexSponge, Permutation};

        thread_local! { static CALLS: Cell<usize> = const { Cell::new(0) }; }
        #[derive(Clone, Default)]
        struct Rotate;
        impl Permutation<40> for Rotate {
            type U = u8;
            fn permute_mut(&self, state: &mut [u8; 40]) {
                for byte in state {
                    *byte = byte.rotate_left(1);
                }
                CALLS.with(|calls| calls.set(calls.get() + 1));
            }
        }
        // Rotate is a toy bijection, not a cryptographic backend. This test
        // checks the real duplex sponge's permutation scheduling, not security.
        type CountingDuplex = DuplexSponge<Rotate, 40, 16>;
        let session = Narg::derive_session_id(b"pow/tests/permutation-cost");
        for (padding, proof, challenge_len, expected_calls) in [
            (11, &[0][..], 15, 1),       // nonce ends exactly at the absorb boundary
            (11, &[0][..], 16, 2),       // check + challenge crosses the output boundary
            (12, &[0][..], 15, 2),       // nonce starts after a full absorb block
            (10, &[0x80, 1][..], 15, 1), // two-byte nonce still fits
            (11, &[0x80, 1][..], 15, 2), // two-byte nonce crosses the boundary
        ] {
            let mut verifier = VerifierState::<CountingDuplex>::new(&session, &0u32, proof);
            for _ in 0..padding {
                verifier.public_message(&0u8);
            }
            CALLS.with(|calls| calls.set(0));
            if challenge_len == 15 {
                verifier.verifier_message_pow::<[u8; 15]>(1).unwrap();
            } else {
                verifier.verifier_message_pow::<[u8; 16]>(1).unwrap();
            }
            assert_eq!(CALLS.with(Cell::get), expected_calls);
            verifier.check_eof().unwrap();
        }
    }

    #[test]
    fn nonce_and_check_sizes_per_difficulty() {
        use super::{accepts, last_nonce, max_nonce_len, word_len, Leb128};
        let layout = |bits| (last_nonce(bits), max_nonce_len(bits), word_len(bits));
        assert_eq!(layout(1), (255, 2, 1));
        assert_eq!(layout(8), ((1 << 15) - 1, 3, 1));
        assert_eq!(layout(10), ((1 << 17) - 1, 3, 2));
        assert_eq!(layout(25), (u64::from(u32::MAX), 5, 4));
        assert_eq!(layout(57), (u64::MAX, 10, 8));
        for bits in 1..=57 {
            assert_eq!(
                Leb128::new(last_nonce(bits)).as_bytes().len(),
                max_nonce_len(bits)
            );
        }
        for bits in [1, 7, 8, 9, 56, 57] {
            assert!(accepts(bits, [0; 8]));
            for bit in 0..64 {
                let word = (1u64 << bit).to_le_bytes();
                assert_eq!(accepts(bits, word), bit >= bits, "bits={bits}, bit={bit}");
            }
        }
    }

    #[test]
    fn verifier_message_pow_search_finds_a_lone_nonce_anywhere_in_the_space() {
        use super::{last_nonce, TranscriptPoW};
        use crate::PoWGrinder;
        for bits in [1] {
            let last = last_nonce(bits);
            for target in [None, Some(127), Some(128), Some(last)] {
                let evaluate = |candidate: &[u8], out: &mut [u8]| {
                    let hit = target.is_some_and(|nonce| candidate == reference_nonce(nonce));
                    out.fill(if hit { 0 } else { 0xff });
                };
                assert_eq!(
                    PoWGrinder::new(TranscriptPoW::new(evaluate, bits)).grind(),
                    target
                );
                #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
                for workers in [1, 3, 4] {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(workers)
                        .build()
                        .unwrap();
                    assert_eq!(
                        pool.install(
                            || PoWGrinder::new(TranscriptPoW::new(evaluate, bits)).grind_parallel()
                        ),
                        target
                    );
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "bits must be at most 57")]
    fn verifier_message_pow_rejects_unsupported_difficulty() {
        let _ = prover().verifier_message_pow::<u64>(58);
    }

    #[test]
    fn every_truncated_nonce_is_rejected() {
        // The largest nonce is valid at 57 bits; every proper prefix is incomplete.
        let proof = leb128(u64::MAX);
        for length in 0..proof.len() {
            let mut verifier = recording_verifier(&proof[..length]);
            assert!(verifier.verifier_message_pow::<u64>(57).is_err());
            assert!(!events()
                .iter()
                .any(|event| matches!(event, Event::Squeeze(_))));
            assert!(verifier.check_eof().is_err());
        }
    }
}
