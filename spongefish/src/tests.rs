use rand::Rng;
use shake::{ExtendableOutput, Update, XofReader};

use crate::{
    derive_session_id, Encoding, NargDeserialize, ProverState, StdHash, VerificationError,
    VerifierState,
};

fn test_session_id(tag: &[u8]) -> [u8; 32] {
    derive_session_id::<StdHash>(tag)
}

#[test]
fn prover_rng_emits_entropy() {
    let instance = [42u32, 7u32];
    let session_id = test_session_id(b"rng test");
    let mut prover = ProverState::<StdHash>::new(&session_id, &instance);

    let mut first = [0u8; 32];
    prover.rng().fill_bytes(&mut first);
    let mut second = [0u8; 32];
    prover.rng().fill_bytes(&mut second);

    assert_ne!(first, [0u8; 32]);
    assert_ne!(first, second);
}

#[test]
fn prover_messages_round_trip() {
    let instance = [1u32, 2u32];
    let session_id = test_session_id(b"round trip");

    let mut prover = ProverState::<StdHash>::new(&session_id, &instance);
    prover.public_message(&instance[0]);
    prover.prover_message(&instance[1]);
    let proof = prover.narg_string().to_vec();

    let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, &proof);
    verifier.public_message(&instance[0]);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), instance[1]);
    assert!(verifier.check_eof().is_ok());
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

#[test]
fn verifier_challenge_matches_prover() {
    let instance = [10u32, 11u32];
    let session_id = test_session_id(b"challenge sync");

    let mut prover = ProverState::<StdHash>::new(&session_id, &instance);
    let challenge: u32 = prover.verifier_message();
    let proof = prover.narg_string().to_vec();

    let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, &proof);
    let reproduced: u32 = verifier.verifier_message();
    assert_eq!(challenge, reproduced);
}

#[test]
fn distinct_session_ids_diverge() {
    let instance = [3u32];

    let mut a = ProverState::<StdHash>::new(&test_session_id(b"session A"), &instance);
    let mut b = ProverState::<StdHash>::new(&test_session_id(b"session B"), &instance);

    let ca: u32 = a.verifier_message();
    let cb: u32 = b.verifier_message();
    assert_ne!(ca, cb);
}

#[test]
fn derive_session_id_is_deterministic() {
    assert_eq!(test_session_id(b"same tag"), test_session_id(b"same tag"));
    assert_ne!(test_session_id(b"tag one"), test_session_id(b"tag two"));
}

/// `DeriveSessionID` must match the draft's construction: the SHAKE128 XOF
/// over `"irtf-cfrg-fiat-shamir/session-id" || zeros(136) || tag`.
#[test]
fn session_id_matches_draft_construction() {
    let mut initial_block = [0u8; 168];
    initial_block[..32].copy_from_slice(b"irtf-cfrg-fiat-shamir/session-id");

    let mut xof = shake::Shake128::default();
    xof.update(&initial_block);
    xof.update(b"discrete_logarithm");
    let mut reader = xof.finalize_xof();
    let mut expected = [0u8; 32];
    reader.read(&mut expected);

    assert_eq!(
        derive_session_id::<crate::instantiations::Shake128>(b"discrete_logarithm"),
        expected
    );
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
    xof.update(&session_id);
    xof.update(&[0u8; 136]);
    xof.update(instance.encode().as_ref());
    let mut reader = xof.finalize_xof();
    let mut expected = [0u8; 32];
    reader.read(&mut expected);

    assert_eq!(challenge, expected);
}

#[test]
fn verifier_prover_message_rolls_back_on_deserialize_error() {
    struct BadMessage;

    impl NargDeserialize for BadMessage {
        fn deserialize_from_narg(buf: &mut &[u8]) -> crate::VerificationResult<Self> {
            *buf = &buf[1..];
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

#[test]
fn str_encoding_prefixes_utf8_with_le_u32_length() {
    let encoded = "hello".encode();
    assert_eq!(encoded.as_ref(), b"\x05\x00\x00\x00hello");

    let encoded_utf8 = "hé".encode();
    assert_eq!(encoded_utf8.as_ref(), b"\x03\x00\x00\x00h\xc3\xa9");
}
