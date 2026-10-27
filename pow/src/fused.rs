//! Proof-of-work-protected verifier messages using the public duplex sponge.
//!
//! This module connects the proof-of-work utilities to the transcript API.
//! Proof of work must be bound to the generation of the next verifier message.
//! A separate proof-of-work check alone does not guarantee multiplicative soundness amplification.
//! The helper keeps nonce absorption, verification, and verifier-message generation together.
//!
//! The prover searches for a nonce whose absorption makes the first `bits` bits
//! of the next verifier output zero. Both parties check those bits and then
//! obtain the protected verifier message from the following output.

use spongefish::{Encoding, FromNarg, NargReader, VerificationError};

use crate::PowStrategy;

/// A proof of work on the public duplex sponge itself.
///
/// For `bits > 0`, the prover sends a nonce below `2^(bits + 7)` as
/// canonical LEB128: seven bits per byte, least significant first, the
/// high bit set on every byte but the last, and no trailing zero byte. Both
/// parties then squeeze `ceil(bits / 8)` bytes and accept the nonce iff
/// their low `bits` bits are zero, then return the protected verifier
/// message. For `bits == 0`, it returns an ordinary verifier message without
/// a nonce or check bytes.
///
/// The returned message is protected, as are further verifier messages up to the
/// next prover message. A type implementing [`FromUniform`](spongefish::FromUniform) can bundle a
/// group of protected challenges into one returned message.
///
/// The prover sends the least accepted nonce. It is below 128, and takes one
/// byte, with probability `1 - (1 - 2^-bits)^128`: at least `1 - e^-8` for
/// `bits <= 4`. The nonce space holds `2^7` times the expected number of
/// trials, so for an ideal duplex sponge an honest search fails with probability
/// at most `e^-128`. This method always searches sequentially (see
/// *Prover performance*). The `parallel` feature provides
/// `verifier_message_pow_parallel` for concrete provers; both paths return
/// the same least nonce and produce identical proofs.
///
/// # Security
///
/// For a fresh ideal duplex sponge output, the check passes with
/// probability `2^-bits`, and conditioning only on that check leaves the
/// bytes that follow uniform. A cheating prover can also select on the
/// protected messages, paying for both conditions. The soundness of the
/// whole protocol depends on its state-restoration soundness, on the
/// backend's reduction to an ideal primitive, and on the decoding bias of
/// the protected messages. Chiesa and Orrù give such a reduction, with an
/// additive error, for the permutation-backed overwrite duplex sponge; it
/// does not by itself cover the digest and XOF bridges. The difficulty, the
/// position of this step and the messages it protects must be fixed by the
/// protocol and bound in its session.
///
/// # Cost
///
/// This step needs no separate proof-of-work hash and no grinding
/// challenge. With a permutation-backed duplex sponge, when the nonce fits in the
/// current absorb block and the check and the protected messages fit in one
/// rate block, each search trial costs one permutation call and the
/// verifier needs one permutation after the nonce. Other alignments, longer
/// outputs and other backends can cost more.
///
/// # Prover performance
///
/// The search runs on the calling thread, one candidate at a time, with the
/// backend's scalar duplex sponge: each trial clones the public sponge,
/// absorbs the nonce and squeezes the check bytes. In `v0.8.0`, this
/// method searched a separate BLAKE3 or Keccak hash on all Rayon threads,
/// with SIMD batches for BLAKE3. At the same difficulty, grinding through
/// this method, including inside [`Argument::run`](spongefish::Argument::run)
/// and the [`FiatShamir`](spongefish::FiatShamir) prover, is therefore
/// slower. In one measurement at 20 bits with `DefaultHash` on a 10-core
/// machine, this method ran about 35 times fewer trials per second than
/// the `v0.8.0` BLAKE3 search, and `verifier_message_pow_parallel` about 6
/// times fewer.
///
/// This method cannot dispatch to the parallel search. Parallel jobs need
/// a `Send` evaluator, and [`Transcript::verifier_message_oracle`](spongefish::Transcript::verifier_message_oracle) does not
/// promise one, so that [`ProverState`](spongefish::ProverState) keeps
/// accepting duplex sponges that are not `Send`. Lifting this limitation
/// needs a `Send` bound on that evaluator, and hence on the public duplex
/// sponge of every prover, or a new hook on [`Transcript`](spongefish::Transcript). Code that holds
/// a concrete `ProverState` with a `Send` public sponge can call
/// `verifier_message_pow_parallel` instead; it writes the same proof.
///
/// # Errors
///
/// The prover returns [`VerificationError`] if the search exhausts the
/// nonce space, or if the [`Transcript`](spongefish::Transcript) implementation does not support
/// [`Transcript::verifier_message_oracle`](spongefish::Transcript::verifier_message_oracle) and rejects the resulting unknown prover
/// message, as [`ProverState`](spongefish::ProverState) does. The prover
/// also replays the check on its own transcript, in release builds too,
/// and returns the error if the replay rejects the nonce it found. This
/// happens only with a duplex sponge whose absorb and squeeze are not
/// associative, as [`DuplexSpongeInterface`](spongefish::DuplexSpongeInterface)
/// requires; the prover then reports an error instead of writing an
/// invalid proof. For
/// `bits > 0`, the verifier returns it if the nonce is not canonical,
/// exceeds the nonce space or misses the target, or if the proof is
/// truncated. At any difficulty, an earlier failed read or check also
/// rejects the step.
///
/// # Panics
///
/// Panics if `bits > 57`. Above that, a `u64` nonce no longer leaves `2^7`
/// times the expected work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FusedPowConfig {
    bits: u32,
}

impl FusedPowConfig {
    /// Configure fused PoW at a protocol-fixed difficulty, from 0 through 57.
    ///
    /// # Panics
    /// Panics if `bits > 57`.
    pub const fn new(bits: u32) -> Self {
        assert!(bits <= MAX_BITS, "bits must be at most 57");
        Self { bits }
    }
}

impl PowStrategy for FusedPowConfig {
    type Nonce = Leb128;

    fn enabled(&self) -> bool {
        self.bits != 0
    }

    fn last_nonce(&self) -> u64 {
        last_nonce(self.bits)
    }

    fn challenge_len(&self) -> usize {
        word_len(self.bits)
    }

    fn accepts(&self, _nonce: u64, challenge: &[u8]) -> bool {
        let mut word = [0; 8];
        word[..challenge.len()].copy_from_slice(challenge);
        accepts(self.bits, word)
    }
}

// Reserve 2^7 times the expected work in the u64 nonce space.
const MAX_BITS: u32 = 57;

const fn last_nonce(bits: u32) -> u64 {
    u64::MAX >> (MAX_BITS - bits)
}

const fn word_len(bits: u32) -> usize {
    (bits as usize).div_ceil(8)
}

const fn accepts(bits: u32, word: [u8; 8]) -> bool {
    u64::from_le_bytes(word) & ((1u64 << bits) - 1) == 0
}

/// A canonical unsigned LEB128 nonce, with no redundant trailing zero byte.
#[derive(Clone, Copy)]
pub struct Leb128(u64);

impl From<u64> for Leb128 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Leb128> for u64 {
    fn from(value: Leb128) -> Self {
        value.0
    }
}

impl Encoding for Leb128 {
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut value = self.0;
        let mut bytes = [0; 10];
        let mut len = 0;
        loop {
            bytes[len] = (value & 0x7f) as u8;
            value >>= 7;
            len += 1;
            if value == 0 {
                return Leb128Bytes { bytes, len };
            }
            bytes[len - 1] |= 0x80;
        }
    }
}

struct Leb128Bytes {
    bytes: [u8; 10],
    len: usize,
}

impl AsRef<[u8]> for Leb128Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl FromNarg for Leb128 {
    fn from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
        let mut value = 0u64;
        for i in 0..10 {
            let byte: u8 = reader.read()?;
            if i == 9 && byte > 1 {
                return Err(VerificationError);
            }
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return if i == 0 || byte != 0 {
                    Ok(Self(value))
                } else {
                    Err(VerificationError)
                };
            }
        }
        Err(VerificationError)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use spongefish::{
        instantiations::{Shake128, TurboShake128},
        DuplexSpongeInit, DuplexSpongeInterface, Narg, ProverState, Transcript, VerificationError,
        VerifierState, Witness,
    };

    use super::FusedPowConfig;
    use crate::{verifier_message_pow_parallel, PowTranscriptExt};
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
    fn missing_prover_oracle_returns_an_error_before_writing_a_nonce() {
        struct MissingOracle;

        impl Transcript for MissingOracle {
            fn prover_message<T>(&mut self, _value: Witness<T>) -> Result<T, VerificationError>
            where
                T: spongefish::Encoding + spongefish::FromNarg,
            {
                panic!("a missing oracle must fail before writing a nonce")
            }

            fn verifier_message<T: spongefish::FromUniform>(&mut self) -> T {
                panic!("a missing oracle must not produce a protected challenge")
            }

            fn public_message<T: spongefish::Encoding + ?Sized>(&mut self, _value: &T) {
                panic!("unexpected public message")
            }

            fn prover_only<T>(&self, compute: impl FnOnce() -> T) -> Witness<T> {
                Witness::known(compute())
            }

            fn sample<T: spongefish::FromUniform>(&mut self) -> Witness<T> {
                panic!("PoW must not sample private randomness")
            }

            fn sample_vec<T: spongefish::FromUniform>(&mut self, _n: usize) -> Witness<Vec<T>> {
                panic!("PoW must not sample private randomness")
            }

            fn check(&self, _holds: impl FnOnce() -> bool) -> Result<(), VerificationError> {
                panic!("a missing oracle must fail before checking a nonce")
            }
        }

        assert!(MissingOracle
            .verifier_message_pow::<u64>(FusedPowConfig::new(1))
            .is_err());
    }

    #[test]
    fn exhausted_grinding_returns_an_error_without_sending_a_nonce() {
        let session_id = Narg::derive_session_id(b"pow/tests/exhausted");
        let mut prover =
            ProverState::<RecordingSponge<255>>::new_with_seed(&session_id, &0u32, [7; 32]);
        assert!(prover
            .verifier_message_pow::<u64>(FusedPowConfig::new(1))
            .is_err());
        assert_eq!(prover.into_narg_string(), b"");
        let mut parallel =
            ProverState::<RecordingSponge<255>>::new_with_seed(&session_id, &0u32, [7; 32]);
        assert!(
            verifier_message_pow_parallel::<u64>(&mut parallel, FusedPowConfig::new(1)).is_err()
        );
        assert_eq!(parallel.into_narg_string(), b"");
    }

    #[test]
    fn rejected_nonce_blocks_challenge_and_poisoning_persists() {
        let session_id = Narg::derive_session_id(b"pow/tests/rejected");
        let mut verifier = VerifierState::<RecordingSponge<255>>::new(&session_id, &0u32, &[0]);
        EVENTS.with_borrow_mut(Vec::clear);
        assert!(verifier
            .verifier_message_pow::<u64>(FusedPowConfig::new(8))
            .is_err());
        // Only the check byte is squeezed; no protected challenge is produced.
        assert_eq!(events(), [Event::Absorb(vec![0]), Event::Squeeze(1)]);
        assert!(verifier
            .verifier_message_pow::<u64>(FusedPowConfig::new(0))
            .is_err());
        assert_eq!(events(), [Event::Absorb(vec![0]), Event::Squeeze(1)]);
        assert!(verifier
            .check(|| panic!("a failed check must not run again"))
            .is_err());
        assert!(verifier.prover_message::<u8>().is_err());
        assert!(verifier.prover_messages_vec::<u8>(0).is_err());
        assert!(verifier
            .verifier_message_pow::<u64>(FusedPowConfig::new(8))
            .is_err());
        assert!(verifier.check_eof().is_err());
    }

    fn leb128(nonce: u64) -> Vec<u8> {
        spongefish::Encoding::encode(&super::Leb128::from(nonce))
            .as_ref()
            .to_vec()
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
    fn roundtrips_match_an_independent_manual_reference() {
        for (bits, padding, skipped) in [
            (0, 0, 0),
            (1, 0, 0),
            (7, 163, 152),
            (8, 0, 0),
            (9, 164, 152),
        ] {
            assert_round::<TurboShake128>(bits, padding, skipped);
        }
        for (bits, padding, skipped) in [
            (0, 0, 0),
            (1, 0, 0),
            (7, 131, 120),
            (8, 0, 0),
            (9, 132, 120),
        ] {
            assert_round::<spongefish::instantiations::Keccak>(bits, padding, skipped);
        }
    }

    fn assert_round<H: DuplexSpongeInit<U = u8> + Send>(bits: u32, padding: usize, skipped: usize) {
        let session = Narg::derive_session_id(b"pow/tests/vectors/v1");
        let (proof, challenge, following) = reference_round::<H>(bits, padding, skipped);
        let mut prover = ProverState::<H, Shake128>::new_with_seed(&session, &0u32, [7; 32]);
        for _ in 0..padding {
            prover.public_message(&42u8);
        }
        assert_eq!(
            prover
                .verifier_message_pow::<u64>(FusedPowConfig::new(bits))
                .unwrap(),
            challenge
        );
        for _ in 0..skipped {
            let _ = prover.verifier_message::<u8>();
        }
        assert_eq!(prover.verifier_message::<u64>(), following);
        assert_eq!(prover.into_narg_string(), proof);
        let mut verifier = VerifierState::<H>::new(&session, &0u32, &proof);
        for _ in 0..padding {
            verifier.public_message(&42u8);
        }
        assert_eq!(
            verifier
                .verifier_message_pow::<u64>(FusedPowConfig::new(bits))
                .unwrap(),
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
                    verifier_message_pow_parallel::<u64>(&mut parallel, FusedPowConfig::new(bits))
                        .unwrap(),
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
                verifier
                    .verifier_message_pow::<u64>(FusedPowConfig::new(bits))
                    .is_ok(),
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
                verifier
                    .verifier_message_pow::<u64>(FusedPowConfig::new(bits))
                    .is_err(),
                "{proof:?}"
            );
            assert!(verifier.check_eof().is_err());
        }
        // The largest nonce is valid at 57 bits; every proper prefix is incomplete.
        let proof = leb128(u64::MAX);
        for length in 0..proof.len() {
            let mut verifier = recording_verifier(&proof[..length]);
            assert!(verifier
                .verifier_message_pow::<u64>(FusedPowConfig::new(57))
                .is_err());
            assert!(!events()
                .iter()
                .any(|event| matches!(event, Event::Squeeze(_))));
            assert!(verifier.check_eof().is_err());
        }
    }

    #[test]
    fn acceptance_checks_exactly_the_requested_low_bits() {
        use super::accepts;

        for bits in [0, 1, 7, 8, 9, 56, 57] {
            assert!(accepts(bits, [0; 8]));
            for bit in 0..64 {
                let word = (1u64 << bit).to_le_bytes();
                assert_eq!(accepts(bits, word), bit >= bits, "bits={bits}, bit={bit}");
            }
        }
    }

    #[test]
    #[should_panic(expected = "bits must be at most 57")]
    fn verifier_message_pow_rejects_unsupported_difficulty() {
        let _ = FusedPowConfig::new(58);
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
        assert!(prover
            .verifier_message_pow::<u64>(FusedPowConfig::new(9))
            .is_err());
        #[cfg(feature = "parallel")]
        {
            let mut parallel =
                ProverState::<NonAssociativeSponge>::new_with_seed(&session_id, &0u32, [7; 32]);
            assert!(crate::verifier_message_pow_parallel::<u64>(
                &mut parallel,
                FusedPowConfig::new(9)
            )
            .is_err());
        }
    }
}
