use alloc::format;

use shake::{ExtendableOutput, Update, XofReader};

use crate::{
    derive_session_id, Argument, DefaultHash, Encoding, FromNarg, Narg, PrivateRng, ProverState,
    SessionId, Transcript, VerificationError, VerifierState, Witness,
};

fn test_session_id(tag: &[u8]) -> SessionId {
    Narg::derive_session_id(tag)
}

/// A poisoned verifier refuses every later read, even one the bytes would
/// satisfy, and has no unread rest to hand back.
fn assert_poisoned(mut verifier: VerifierState<'_, DefaultHash>) {
    assert!(verifier.prover_message::<u8>().is_err());
    assert!(verifier.prover_messages::<u8, 0>().is_err());
    assert!(verifier.prover_messages_vec::<u8>(0).is_err());
    assert!(verifier
        .prover_messages_vec_as::<u8>(0, |_| panic!("empty batch must not invoke its parser"))
        .is_err());
    assert!(verifier.into_narg_string().is_err());
}

#[test]
fn witness_debug_is_redacted() {
    assert_eq!(format!("{:?}", Witness::known("witness")), "Witness(..)");
    assert_eq!(format!("{:?}", Witness::<&str>::unknown()), "Witness(..)");
}

#[test]
fn transcript_checks_preserve_rejection_after_caught_errors() {
    let session = test_session_id(b"failed transcript check");
    for consumed in [false, true] {
        let mut verifier = VerifierState::<DefaultHash>::new(&session, &0u32, &[1]);
        if consumed {
            assert_eq!(verifier.prover_message::<u8>().unwrap(), 1);
        }
        let shared = &verifier;
        assert!(shared.check(|| false).is_err());
        assert!(shared
            .check(|| panic!("check must not run after rejection"))
            .is_err());
        assert_poisoned(verifier);
    }

    let verifier = VerifierState::<DefaultHash>::new(&session, &0u32, &[]);
    assert!(verifier.check(|| false).is_err());
    assert!(verifier.check_eof().is_err());

    let mut verifier = VerifierState::<DefaultHash>::new(&session, &0u32, &[]);
    assert!(verifier.prover_message::<u8>().is_err());
    assert!(verifier
        .check(|| panic!("check must not run after a failed read"))
        .is_err());
    assert!(verifier.check_eof().is_err());
}

#[test]
fn successful_transcript_checks_preserve_messages_and_challenges() {
    let session = test_session_id(b"successful transcript check");
    let mut verifier = VerifierState::<DefaultHash>::new(&session, &0u32, &[7]);
    let mut reference = VerifierState::<DefaultHash>::new(&session, &0u32, &[7]);
    let shared = &verifier;
    assert!(shared.check(|| shared.check(|| true).is_ok()).is_ok());
    assert_eq!(verifier.prover_message::<u8>().unwrap(), 7);
    assert_eq!(reference.prover_message::<u8>().unwrap(), 7);
    assert!(verifier.check(|| true).is_ok());
    assert_eq!(
        verifier.verifier_message::<[u8; 32]>(),
        reference.verifier_message::<[u8; 32]>()
    );
    assert!(verifier.check_eof().is_ok());
}

#[test]
fn transcript_checks_reject_caught_nested_failures() {
    let session = test_session_id(b"nested transcript check");
    let verifier = VerifierState::<DefaultHash>::new(&session, &0u32, &[]);
    assert!(verifier
        .check(|| {
            assert!(verifier.check(|| false).is_err());
            true
        })
        .is_err());
    assert!(verifier
        .check(|| panic!("check must not run after nested rejection"))
        .is_err());
    assert!(verifier.check_eof().is_err());
}

#[test]
fn argument_cannot_accept_a_caught_verification_failure() {
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
            let _ = transcript.check(|| false);
            Ok(())
        }
    }
    assert!(Narg::verify::<SwallowsFailure>(b"caught check failure", &0, &[]).is_err());
}

#[test]
fn seeded_prover_rng_is_deterministic_and_mixing_diverges() {
    let instance = [1u32];
    let session_id = test_session_id(b"seeded rng");
    let seed = [7u8; 32];

    let mut a = ProverState::<DefaultHash>::new_with_seed(&session_id, &instance, seed);
    let mut b = ProverState::<DefaultHash>::new_with_seed(&session_id, &instance, seed);
    let (mut ra, mut rb) = ([0u8; 32], [0u8; 32]);
    a.rng().fill_bytes(&mut ra);
    b.rng().fill_bytes(&mut rb);
    assert_eq!(ra, rb);

    let mut c = ProverState::<DefaultHash>::new_with_seed(&session_id, &instance, seed);
    c.mix_entropy(&[9u8; 32]);
    let mut rc = [0u8; 32];
    c.rng().fill_bytes(&mut rc);
    assert_ne!(ra, rc);
}

#[test]
fn sample_vec_matches_repeated_sampling() {
    let seed = [11u8; 32];
    let mut vector_rng = PrivateRng::<DefaultHash>::from_seed(seed);
    let mut repeated_rng = PrivateRng::<DefaultHash>::from_seed(seed);

    let samples = vector_rng.sample_vec::<u32>(4);
    let expected = (0..4)
        .map(|_| repeated_rng.sample::<u32>())
        .collect::<alloc::vec::Vec<_>>();

    assert_eq!(samples, expected);
    assert_eq!(vector_rng.sample_vec::<u32>(0), [] as [u32; 0]);
}

#[test]
fn check_eof_reports_remaining_bytes() {
    let instance = [5u32, 6u32];
    let session_id = test_session_id(b"check eof");

    let mut prover = ProverState::<DefaultHash>::new(&session_id, &instance);
    prover.prover_message(&instance[0]);
    let mut proof = prover.narg_string().to_vec();
    proof.extend_from_slice(&[9u8, 9, 9, 9]);

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), instance[0]);
    assert!(verifier.check_eof().is_err());
}

#[test]
fn into_narg_string_returns_the_unread_rest() {
    let instance = [5u32];
    let session_id = test_session_id(b"into narg string");

    let mut prover = ProverState::<DefaultHash>::new(&session_id, &instance);
    prover.prover_message(&instance[0]);
    let mut proof = prover.into_narg_string();

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), instance[0]);
    assert_eq!(verifier.into_narg_string().unwrap(), []);

    proof.extend_from_slice(&[9, 9, 9, 9]);
    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), instance[0]);
    assert_eq!(verifier.into_narg_string().unwrap(), [9, 9, 9, 9]);
}

/// The verifier messages are the XOF over
/// `session_id || zeros(136) || encode(instance) || ...`.
#[test]
fn initialization_matches_manual_shake128() {
    let session_id = derive_session_id::<crate::instantiations::Shake128>(b"discrete_logarithm");
    let instance = [42u32, 7u32];

    let mut prover = ProverState::<crate::instantiations::Shake128>::new(&session_id, &instance);
    let challenge: [u8; 32] = prover.verifier_message();

    let mut xof = shake::Shake128::default();
    xof.update(session_id.as_bytes());
    xof.update(&[0u8; 136]);
    xof.update(instance.encode().as_ref());
    let mut reader = xof.finalize_xof();
    let mut expected = [0u8; 32];
    reader.read(&mut expected);

    assert_eq!(challenge, expected);
}

#[test]
fn closure_codecs_correctness() {
    struct Foreign(u64);

    let instance = [9u32];
    let session_id = test_session_id(b"closure codecs");

    let value = Foreign(0xdead_beef);
    let proof = ProverState::<DefaultHash>::new(&session_id, &instance)
        .last_prover_message_as(&value, |v| v.0.to_le_bytes());

    let read = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof)
        .last_prover_message_as(|reader| {
            let bytes = reader.take_array()?;
            Ok(Foreign(u64::from_le_bytes(bytes)))
        })
        .unwrap();
    assert_eq!(read.0, value.0);
}

#[test]
fn verifier_prover_message_poisons_on_deserialize_error() {
    struct BadMessage;

    impl FromNarg for BadMessage {
        fn from_narg(reader: &mut crate::NargReader<'_>) -> Result<Self, VerificationError> {
            // Consumes input and *then* fails: the verifier must end up
            // poisoned, not merely advanced.
            reader.take(1)?;
            Err(VerificationError)
        }
    }

    impl crate::Encoding for BadMessage {
        fn encode(&self) -> impl AsRef<[u8]> {
            []
        }
    }

    let proof = [7u8, 8, 9];
    let session_id = test_session_id(b"poison");
    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, b"instance", &proof);
    assert!(verifier.prover_message::<BadMessage>().is_err());

    // Nothing was absorbed: the public coins match a verifier that never read.
    let mut untouched = VerifierState::<DefaultHash>::new(&session_id, b"instance", &proof);
    assert_eq!(
        verifier.verifier_message::<[u8; 32]>(),
        untouched.verifier_message::<[u8; 32]>()
    );
    assert_poisoned(verifier);
}

#[test]
fn a_failed_read_poisons_the_reader() {
    struct Rejected;

    impl FromNarg for Rejected {
        fn from_narg(_: &mut crate::NargReader<'_>) -> Result<Self, VerificationError> {
            Err(VerificationError)
        }
    }

    let bytes = [1u8, 2, 3];

    // A short read.
    let mut reader = crate::NargReader::new(&bytes);
    assert!(reader.take_array::<4>().is_err());
    assert!(reader.is_poisoned());
    assert!(reader.take(1).is_err());
    assert!(reader.take_array::<1>().is_err());
    assert!(reader.read::<u8>().is_err());
    assert!(!reader.is_empty());

    // A deserializer's own rejection, with input to spare.
    let mut reader = crate::NargReader::new(&bytes);
    assert!(reader.read::<Rejected>().is_err());
    assert!(reader.is_poisoned());
    assert!(reader.take(1).is_err());

    // A rejection after the last byte: a poisoned reader is never empty.
    let mut reader = crate::NargReader::new(&bytes);
    assert_eq!(reader.take_array::<3>().unwrap(), bytes);
    assert!(reader.is_empty());
    assert!(reader.read::<Rejected>().is_err());
    assert!(!reader.is_empty());
}

#[test]
fn verifier_rejects_a_message_that_swallowed_a_failed_read() {
    struct Lenient(u8);

    impl FromNarg for Lenient {
        fn from_narg(reader: &mut crate::NargReader<'_>) -> Result<Self, VerificationError> {
            // Substitutes a default for a short read instead of failing.
            Ok(Self(reader.take_array::<8>().map_or(0, |bytes| bytes[0])))
        }
    }

    impl crate::Encoding for Lenient {
        fn encode(&self) -> impl AsRef<[u8]> {
            [self.0]
        }
    }

    let proof = [7u8, 8, 9];
    let session_id = test_session_id(b"swallowed");

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, b"instance", &proof);
    assert!(verifier.prover_message::<Lenient>().is_err());
    assert_poisoned(verifier);

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, b"instance", &proof);
    let lenient =
        verifier.prover_message_as(|reader| Ok(reader.take_array::<8>().unwrap_or([0; 8])));
    assert!(lenient.is_err());
    assert_poisoned(verifier);
}

/// A tuple encodes as the concatenation of its components' encodings, at every
/// supported arity — the same bytes the components produce on their own.
#[test]
fn tuple_encoding_concatenates_components() {
    assert_eq!((1u8, 2u16).encode().as_ref(), b"\x01\x02\x00");
    assert_eq!(
        (1u8, 2u16, 3u32).encode().as_ref(),
        b"\x01\x02\x00\x03\x00\x00\x00"
    );

    // The widest arity, and a nested tuple: both are just concatenation.
    let wide = (1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8);
    assert_eq!(wide.encode().as_ref(), &[1u8, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(((1u8, 2u8), (3u8, 4u8)).encode().as_ref(), &[1u8, 2, 3, 4]);

    // A component whose own encoding is length-prefixed keeps that prefix, so
    // the concatenation stays prefix-free.
    assert_eq!((1u8, "hi").encode().as_ref(), b"\x01\x02\x00\x00\x00hi");
}

mod word_sponge {
    use crate::duplex_sponge::{DuplexSponge, Permutation};

    /// Toy ARX permutation over four `u64` words. Deterministic mixing with no
    /// security claim; it exists to exercise the generic-alphabet
    /// (`H::U != u8`) API surface.
    #[derive(Clone, Default)]
    pub struct ToyPermutation;

    impl Permutation<4> for ToyPermutation {
        type U = u64;

        fn permute_mut(&self, s: &mut [u64; 4]) {
            for _ in 0..8 {
                s[0] = s[0].wrapping_add(s[1]).rotate_left(13) ^ s[2];
                s[1] = s[1].wrapping_add(s[2]).rotate_left(29) ^ s[3];
                s[2] = s[2].wrapping_add(s[3]).rotate_left(43) ^ s[0];
                s[3] = s[3].wrapping_add(s[0]).rotate_left(7) ^ s[1];
            }
        }
    }

    pub type WordSponge = DuplexSponge<ToyPermutation, 4, 2>;

    /// One word per session-identifier byte.
    impl crate::EncodedSessionId for u64 {
        fn encode_bytes(bytes: &[u8]) -> impl AsRef<[Self]> {
            bytes
                .iter()
                .map(|&b| Self::from(b))
                .collect::<alloc::vec::Vec<_>>()
        }
    }

    pub struct Words(pub [u64; 2]);

    impl crate::Encoding<u64> for Words {
        fn encode(&self) -> impl AsRef<[u64]> {
            self.0
        }
    }
}

#[test]
fn closure_codecs_generic_alphabet_round_trip() {
    use word_sponge::{WordSponge, Words};

    struct Foreign(u64);

    let encode = |v: &Foreign| [v.0];
    let value = Foreign(0xdead_beef);

    let session_id = test_session_id(b"generic alphabet");
    let instance = Words([42, 7]);

    let mut prover = ProverState::<WordSponge>::new(&session_id, &instance);
    prover.prover_message_with(&value, encode, |v, out| {
        out.extend_from_slice(&v.0.to_le_bytes());
    });
    prover.public_message_as(&3u64, |v| [*v]);
    let prover_challenge: [u64; 2] = prover.verifier_message_as(2, |units| [units[0], units[1]]);
    let proof = prover.into_narg_string();

    let mut verifier = VerifierState::<WordSponge>::new(&session_id, &instance, &proof);
    let read = verifier
        .prover_message_with(|buf| buf.read::<u64>().map(Foreign), encode)
        .unwrap();
    assert_eq!(read.0, value.0);
    verifier.public_message_as(&3u64, |v| [*v]);
    let verifier_challenge: [u64; 2] =
        verifier.verifier_message_as(2, |units| [units[0], units[1]]);
    assert_eq!(prover_challenge, verifier_challenge);
    assert!(verifier.check_eof().is_ok());
}

/// `prover_message_with` applied to a type's own trait maps must agree with
/// the trait-based `prover_message` — the identity documented on the method.
#[test]
fn prover_message_with_matches_trait_path() {
    let instance = [4u32];
    let session_id = test_session_id(b"with matches trait");

    let mut trait_path = ProverState::<DefaultHash>::new(&session_id, &instance);
    let mut closure_path = ProverState::<DefaultHash>::new(&session_id, &instance);
    trait_path.prover_message(&42u32);
    closure_path.prover_message_with(
        &42u32,
        |x| x.to_le_bytes(),
        |x, dst| dst.extend_from_slice(x.encode().as_ref()),
    );

    assert_eq!(trait_path.narg_string(), closure_path.narg_string());
    let ca: u64 = trait_path.verifier_message();
    let cb: u64 = closure_path.verifier_message();
    assert_eq!(ca, cb);
}

#[test]
fn verifier_prover_message_with_poisons_on_error() {
    let proof = [7u8, 8, 9];
    let session_id = test_session_id(b"with poison");
    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, b"instance", &proof);

    // A deserializer that consumes input and *then* fails poisons the state:
    // nothing is absorbed, and no later read succeeds.
    let result: Result<u64, VerificationError> = verifier.prover_message_with(
        |reader| {
            reader.take(1)?;
            Err(VerificationError)
        },
        |v: &u64| v.to_le_bytes(),
    );
    assert!(result.is_err());
    assert_poisoned(verifier);

    // A deserializer that consumes the whole NARG string is accepted. The
    // `&mut &[u8]` cursor this replaced could not express it: a closure
    // signalling "all consumed" with an empty slice failed the pointer-identity
    // check and had its proof rejected.
    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, b"instance", &proof);
    let result: Result<u64, VerificationError> = verifier.prover_message_with(
        |reader| {
            while !reader.is_empty() {
                reader.take(1)?;
            }
            Ok(3)
        },
        |v: &u64| v.to_le_bytes(),
    );
    assert_eq!(result.unwrap(), 3);
    assert_eq!(verifier.into_narg_string().unwrap(), []);
}

#[test]
fn closure_batch_helpers_round_trip() {
    let instance = [1u32];
    let session_id = test_session_id(b"closure batch");
    let points: [[u8; 4]; 3] = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]];

    let mut prover = ProverState::<DefaultHash>::new(&session_id, &instance);
    prover.prover_messages_as(&points, |point| *point);
    let proof = prover.into_narg_string();
    assert_eq!(proof, points.concat());

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof);
    // A method item fixes the reader's inner lifetime; this closure must work
    // for both lifetimes required by the parser callback.
    #[allow(clippy::redundant_closure_for_method_calls)]
    let read_back = verifier
        .prover_messages_vec_as(points.len(), |reader| reader.take_array::<4>())
        .unwrap();
    assert_eq!(read_back, points);
    assert_eq!(verifier.prover_messages::<u8, 0>().unwrap(), []);
    assert_eq!(verifier.prover_messages_vec::<u8>(0).unwrap(), []);
    assert_eq!(
        verifier
            .prover_messages_vec_as::<u8>(0, |_| panic!("empty batch must not invoke its parser"))
            .unwrap(),
        []
    );
    assert!(verifier.check_eof().is_ok());
}

#[test]
fn terminal_helpers_match_the_non_terminal_path_and_reject_trailing_bytes() {
    let instance = [4u32];
    let session_id = test_session_id(b"terminal matches");

    let mut open = ProverState::<DefaultHash>::new(&session_id, &instance);
    open.prover_message(&1u32);
    open.prover_message(&2u32);

    let mut terminal = ProverState::<DefaultHash>::new(&session_id, &instance);
    terminal.prover_message(&1u32);
    let narg_string = terminal.last_prover_message(&2u32);

    assert_eq!(open.narg_string(), narg_string);

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &narg_string);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), 1);
    assert_eq!(verifier.last_prover_message::<u32>().unwrap(), 2);

    let mut with_trailing = narg_string;
    with_trailing.push(0);
    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &with_trailing);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), 1);
    assert!(verifier.last_prover_message::<u32>().is_err());
}

#[test]
fn witness_transpose_moves_the_error_out_on_the_prover_only() {
    let ok: Witness<Result<u8, VerificationError>> = Witness::known(Ok(7));
    assert_eq!(ok.transpose().unwrap().into_known(), Some(7));

    let err: Witness<Result<u8, VerificationError>> = Witness::known(Err(VerificationError));
    assert!(err.transpose().is_err());

    let unknown: Witness<Result<u8, VerificationError>> = Witness::unknown();
    assert_eq!(unknown.transpose().unwrap().into_known(), None);
}

#[test]
fn witness_copied_and_cloned_follow_option() {
    let value = alloc::vec![1u8, 2];
    let borrowed = Witness::known(&value);
    assert_eq!(borrowed.cloned().into_known(), Some(value.clone()));
    assert_eq!(Witness::known(&3u8).copied().into_known(), Some(3));
    assert_eq!(Witness::<&u8>::unknown().copied().into_known(), None);
}

#[test]
fn prover_only_runs_on_the_prover_and_is_skipped_by_the_verifier() {
    /// Returns a prover-side value the caller recovers from the output, the
    /// shape of a reduction of knowledge.
    struct PublicSquare;
    impl Argument for PublicSquare {
        type Instance = u32;
        type Witness = ();
        type Output = Witness<u64>;

        fn run<T: Transcript>(
            transcript: &mut T,
            instance: &u32,
            _witness: Witness<&()>,
        ) -> Result<Witness<u64>, VerificationError> {
            let square = transcript.prover_only(|| u64::from(*instance).pow(2));
            let sent = transcript.prover_message(square)?;
            transcript.check(|| sent == u64::from(*instance).pow(2))?;
            Ok(square.map(|s| s + 1))
        }
    }

    let tag = b"prover-only";
    let (proof, output) = Narg::prove::<PublicSquare>(tag, &6, &()).unwrap();
    assert_eq!(output.into_known(), Some(37));
    let output = Narg::verify::<PublicSquare>(tag, &6, &proof).unwrap();
    assert_eq!(output.into_known(), None);
    assert!(Narg::verify::<PublicSquare>(tag, &7, &proof).is_err());

    let session = test_session_id(tag);
    let verifier = VerifierState::<DefaultHash>::new(&session, &0u32, &[]);
    let skipped: Witness<u8> = verifier.prover_only(|| panic!("the verifier must not compute"));
    assert_eq!(skipped.into_known(), None);
}

#[test]
fn a_failed_prover_only_computation_fails_the_prover() {
    struct Exhausted;
    impl Argument for Exhausted {
        type Instance = u32;
        type Witness = ();
        type Output = ();

        fn run<T: Transcript>(
            transcript: &mut T,
            _instance: &u32,
            _witness: Witness<&()>,
        ) -> Result<(), VerificationError> {
            let nonce = transcript
                .prover_only(|| Err::<u32, _>(VerificationError))
                .transpose()?;
            transcript.prover_message(nonce).map(|_| ())
        }
    }

    assert!(Narg::prove::<Exhausted>(b"exhausted", &0, &()).is_err());
}

#[test]
fn search_matches_sending_the_candidate_then_squeezing() {
    fn assert_sync<T: Sync>(_: &T) {}

    let session_id = test_session_id(b"message search");
    let new_prover = || {
        let mut prover = ProverState::<DefaultHash>::new_with_seed(&session_id, &[3u32], [1; 32]);
        prover.prover_message(&9u32);
        prover
    };

    let mut probed = new_prover();
    let narg_before = probed.narg_string().to_vec();
    let evaluate = probed.search_verifier_message();
    let retained = evaluate.clone();
    assert_sync(&evaluate);

    let mut predicted = [0u8; 200];
    evaluate(7u64.encode().as_ref(), &mut predicted);
    let delegated = Transcript::search_verifier_message(&probed).map(|evaluate| {
        let mut output = [0u8; 200];
        evaluate(7u64.encode().as_ref(), &mut output);
        output
    });
    assert_eq!(delegated.into_known().unwrap(), predicted);
    // Search leaves the proof, public duplex sponge and private RNG unchanged.
    assert_eq!(probed.narg_string(), narg_before);
    let mut untouched = new_prover();
    assert_eq!(
        probed.rng().sample::<[u8; 32]>(),
        untouched.rng().sample::<[u8; 32]>()
    );
    assert_eq!(
        probed.verifier_message::<[u8; 32]>(),
        untouched.verifier_message::<[u8; 32]>()
    );

    drop(probed);
    let mut replayed = [0u8; 200];
    retained(7u64.encode().as_ref(), &mut replayed);
    assert_eq!(replayed, predicted);

    let mut sent = new_prover();
    sent.prover_message(&7u64);
    assert_eq!(sent.verifier_message::<[u8; 200]>(), predicted);
}

#[test]
fn search_verifier_message_runs_only_on_the_prover() {
    let session_id = test_session_id(b"message search");
    let prover = ProverState::<DefaultHash>::new_with_seed(&session_id, &[3u32], [1; 32]);
    let found = Transcript::search_verifier_message(&prover).map(|evaluate| {
        let mut out = [0u8; 4];
        evaluate(&[1, 2, 3], &mut out);
        out
    });
    assert!(found.into_known().is_some());

    let verifier = VerifierState::<DefaultHash>::new(&session_id, &[3u32], &[]);
    let skipped = Transcript::search_verifier_message(&verifier)
        .map(|_| -> u8 { panic!("the verifier must not run the search") });
    assert!(skipped.into_known().is_none());
}

#[test]
fn generic_search_verifier_message_outlives_the_transcript() {
    fn retained_search<T: Transcript>(mut transcript: T) {
        let evaluate = transcript.search_verifier_message().into_known().unwrap();
        let retained = evaluate.clone();
        let mut expected = [0u8; 32];
        evaluate(&[7], &mut expected);
        transcript.prover_message(Witness::known(9u8)).unwrap();
        drop(transcript);
        let mut actual = [0u8; 32];
        retained(&[7], &mut actual);
        assert_eq!(actual, expected);
    }

    let session_id = test_session_id(b"retained generic search");
    retained_search(ProverState::<DefaultHash>::new_with_seed(
        &session_id,
        &0u32,
        [1; 32],
    ));
}

mod non_sync_backend {
    use core::cell::RefCell;

    use super::*;
    use crate::{DuplexSpongeInit, DuplexSpongeInterface, FiatShamir};

    #[derive(Clone)]
    struct NonSyncSponge(RefCell<DefaultHash>);

    impl DuplexSpongeInterface for NonSyncSponge {
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

    impl DuplexSpongeInit for NonSyncSponge {
        fn init(session_id: &[u8; 32]) -> Self {
            Self(RefCell::new(DefaultHash::init(session_id)))
        }
    }

    struct Round;
    impl Argument for Round {
        type Instance = u32;
        type Witness = ();
        type Output = u64;

        fn run<T: Transcript>(
            transcript: &mut T,
            _instance: &u32,
            _witness: Witness<&()>,
        ) -> Result<u64, VerificationError> {
            let candidate = transcript.search_verifier_message().map(|evaluate| {
                let mut output = [0u8; 8];
                evaluate(&[7], &mut output);
                output
            });
            transcript.prover_message(candidate)?;
            Ok(transcript.verifier_message())
        }
    }

    #[test]
    fn verification_does_not_require_sync() {
        let tag = b"non-sync verification";
        let (proof, challenge) = Narg::prove::<Round>(tag, &0, &()).unwrap();
        assert_eq!(
            FiatShamir::<NonSyncSponge>::verify::<Round>(tag, &0, &proof).unwrap(),
            challenge
        );
    }
    #[test]
    fn proving_does_not_require_sync() {
        let tag = b"non-sync proving";
        let (proof, challenge) = FiatShamir::<NonSyncSponge>::prove::<Round>(tag, &0, &()).unwrap();
        let session = FiatShamir::<NonSyncSponge>::derive_session_id(tag);
        assert_eq!(
            FiatShamir::<NonSyncSponge>::prove_with_session_id::<Round>(&session, &0, &()).unwrap(),
            (proof.clone(), challenge)
        );
        assert_eq!(
            FiatShamir::<NonSyncSponge>::verify::<Round>(tag, &0, &proof).unwrap(),
            challenge
        );
    }
}
