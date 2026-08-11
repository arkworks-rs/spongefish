use alloc::format;

use shake::{ExtendableOutput, Update, XofReader};

use crate::{
    derive_session_id, Argument, DuplexSpongeInterface, Encoding, Narg, NargDeserialize,
    NargSerialize, PrivateRng, ProverState, SessionId, StdHash, Transcript, VerificationError,
    VerificationResult, VerifierState, Witness,
};

fn test_session_id(tag: &[u8]) -> SessionId {
    derive_session_id::<StdHash>(tag)
}

#[test]
fn witness_debug_is_redacted() {
    assert_eq!(format!("{:?}", Witness::known("witness")), "Witness(..)");
    assert_eq!(format!("{:?}", Witness::<&str>::unknown()), "Witness(..)");
}

#[test]
#[should_panic(expected = "an Argument must be zero-sized")]
fn argument_cannot_override_the_statelessness_check() {
    #[allow(dead_code)]
    struct Stateful(u8);

    impl Argument for Stateful {
        const NO_STATE: () = ();

        type Instance = u32;
        type Witness = ();
        type Output = ();

        fn run<T: Transcript>(
            _transcript: &mut T,
            _instance: &Self::Instance,
            _witness: Witness<&Self::Witness>,
        ) -> VerificationResult<Self::Output> {
            Ok(())
        }
    }

    let session_id = test_session_id(b"stateful argument");
    let _ = Narg::prove::<Stateful>(&session_id, &0, &());
}

#[test]
fn seeded_prover_rng_is_deterministic_and_mixing_diverges() {
    let instance = [1u32];
    let session_id = test_session_id(b"seeded rng");
    let seed = [7u8; 32];

    let mut a = ProverState::<StdHash>::new_with_seed(&session_id, &instance, seed);
    let mut b = ProverState::<StdHash>::new_with_seed(&session_id, &instance, seed);
    let (mut ra, mut rb) = ([0u8; 32], [0u8; 32]);
    a.rng().fill_bytes(&mut ra);
    b.rng().fill_bytes(&mut rb);
    assert_eq!(ra, rb);

    let mut c = ProverState::<StdHash>::new_with_seed(&session_id, &instance, seed);
    c.mix_entropy(&[9u8; 32]);
    let mut rc = [0u8; 32];
    c.rng().fill_bytes(&mut rc);
    assert_ne!(ra, rc);
}

#[test]
fn sample_vec_matches_repeated_sampling() {
    let seed = [11u8; 32];
    let mut vector_rng = PrivateRng::<StdHash>::from_seed(seed);
    let mut repeated_rng = PrivateRng::<StdHash>::from_seed(seed);

    let samples = vector_rng.sample_vec::<u32>(4);
    let expected = (0..4)
        .map(|_| repeated_rng.sample::<u32>())
        .collect::<alloc::vec::Vec<_>>();

    assert_eq!(samples, expected);
    assert!(vector_rng.sample_vec::<u32>(0).is_empty());
}

#[test]
fn check_eof_reports_remaining_bytes() {
    let instance = [5u32, 6u32];
    let session_id = test_session_id(b"check eof");

    let mut prover = ProverState::<StdHash>::new(&session_id, &instance);
    prover.prover_message(&instance[0]);
    let mut proof = prover.narg_string().to_vec();
    proof.extend_from_slice(&[9u8, 9, 9, 9]);

    let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, &proof);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), instance[0]);
    assert!(verifier.check_eof().is_err());
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
    let proof = ProverState::<StdHash>::new(&session_id, &instance)
        .last_prover_message_as(&value, |v| v.0.to_le_bytes());

    let read = VerifierState::<StdHash>::new(&session_id, &instance, &proof)
        .last_prover_message_as(|reader| Ok(Foreign(u64::from_le_bytes(reader.take_array()?))))
        .unwrap();
    assert_eq!(read.0, value.0);
}

#[test]
fn verifier_prover_message_rolls_back_on_deserialize_error() {
    struct BadMessage;

    impl NargDeserialize for BadMessage {
        fn deserialize_from_narg(
            reader: &mut crate::NargReader<'_>,
        ) -> crate::VerificationResult<Self> {
            // Consumes input and *then* fails: the reader is left advanced,
            // and the verifier must still not move.
            reader.take(1)?;
            Err(VerificationError)
        }
    }

    impl crate::Encoding<[u8]> for BadMessage {
        fn encode(&self) -> impl AsRef<[u8]> {
            []
        }
    }

    let proof = [7u8, 8, 9];
    let session_id = test_session_id(b"rollback");
    let mut verifier = VerifierState::<StdHash>::new(&session_id, b"instance", &proof);
    assert!(verifier.prover_message::<BadMessage>().is_err());
    assert_eq!(verifier.narg_string, &proof);
    assert!(verifier.check_eof().is_err());
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
}

#[test]
fn closure_codecs_generic_alphabet_round_trip() {
    struct Foreign(u64);

    let encode = |v: &Foreign| [v.0];
    let value = Foreign(0xdead_beef);

    let mut session = word_sponge::WordSponge::default();
    session.absorb(&[42, 7]);

    let mut prover = ProverState::from(session.clone());
    prover.prover_message_with(&value, encode, |v, out| {
        out.extend_from_slice(&v.0.to_le_bytes());
    });
    prover.public_message_as(&3u64, |v| [*v]);
    let prover_challenge: [u64; 2] = prover.verifier_message_as(2, |units| [units[0], units[1]]);
    let proof = prover.into_narg_string();

    let mut verifier = VerifierState::from_parts(session, &proof);
    let read = verifier
        .prover_message_with(|buf| u64::deserialize_from_narg(buf).map(Foreign), encode)
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

    let mut trait_path = ProverState::<StdHash>::new(&session_id, &instance);
    let mut closure_path = ProverState::<StdHash>::new(&session_id, &instance);
    trait_path.prover_message(&42u32);
    closure_path.prover_message_with(
        &42u32,
        |x| x.to_le_bytes(),
        NargSerialize::serialize_into_narg,
    );

    assert_eq!(trait_path.narg_string(), closure_path.narg_string());
    let ca: u64 = trait_path.verifier_message();
    let cb: u64 = closure_path.verifier_message();
    assert_eq!(ca, cb);
}

#[test]
fn verifier_prover_message_with_rolls_back_on_error() {
    let proof = [7u8, 8, 9];
    let session_id = test_session_id(b"with rollback");
    let mut verifier = VerifierState::<StdHash>::new(&session_id, b"instance", &proof);

    // A deserializer that consumes input and *then* fails leaves the cursor
    // unchanged and absorbs nothing: the reader it advanced is discarded.
    let result: VerificationResult<u64> = verifier.prover_message_with(
        |reader| {
            reader.take(1)?;
            Err(VerificationError)
        },
        |v: &u64| v.to_le_bytes(),
    );
    assert!(result.is_err());
    assert_eq!(verifier.narg_string, &proof);

    // A deserializer that consumes the whole NARG string is accepted. The
    // `&mut &[u8]` cursor this replaced could not express it: a closure
    // signalling "all consumed" with an empty slice failed the pointer-identity
    // check and had its proof rejected.
    let result: VerificationResult<u64> = verifier.prover_message_with(
        |reader| {
            reader.take(reader.remaining_len())?;
            Ok(3)
        },
        |v: &u64| v.to_le_bytes(),
    );
    assert_eq!(result.unwrap(), 3);
    assert!(verifier.narg_string.is_empty());
}

#[test]
// The reader closure below is not redundant: the deserializer bound is
// higher-ranked over the reader's lifetime, which a bare
// `NargReader::take_array` method reference cannot satisfy.
#[allow(clippy::redundant_closure_for_method_calls)]
fn closure_batch_helpers_round_trip() {
    let instance = [1u32];
    let session_id = test_session_id(b"closure batch");
    let points: [[u8; 4]; 3] = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]];

    let mut prover = ProverState::<StdHash>::new(&session_id, &instance);
    prover.prover_messages_as(&points, |point| *point);
    let proof = prover.into_narg_string();
    assert_eq!(proof, points.concat());

    let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, &proof);
    let read_back = verifier
        .prover_messages_vec_as(points.len(), |reader| reader.take_array::<4>())
        .unwrap();
    assert_eq!(read_back, points);
    assert!(verifier.check_eof().is_ok());
}

#[test]
fn terminal_helpers_match_the_non_terminal_path_and_reject_trailing_bytes() {
    let instance = [4u32];
    let session_id = test_session_id(b"terminal matches");

    let mut open = ProverState::<StdHash>::new(&session_id, &instance);
    open.prover_message(&1u32);
    open.prover_message(&2u32);

    let mut terminal = ProverState::<StdHash>::new(&session_id, &instance);
    terminal.prover_message(&1u32);
    let narg_string = terminal.last_prover_message(&2u32);

    assert_eq!(open.narg_string(), narg_string);

    let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, &narg_string);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), 1);
    assert_eq!(verifier.last_prover_message::<u32>().unwrap(), 2);

    let mut with_trailing = narg_string;
    with_trailing.push(0);
    let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, &with_trailing);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), 1);
    assert!(verifier.last_prover_message::<u32>().is_err());
}
