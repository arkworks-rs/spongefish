use alloc::string::String;

use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::{DuplexSpongeInterface, Encoding, NargDeserialize, VerificationError};

#[test]
fn prover_rng_emits_entropy() {
    let instance = [42u32, 7u32];
    let domain = crate::domain_separator!("rng test")
        .session(crate::session!("rng session"))
        .instance(&instance);

    let mut prover = domain.std_prover();
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
    let domain = crate::domain_separator!("round trip")
        .without_session()
        .instance(&instance);

    let mut prover = domain.std_prover();
    prover.public_message(&instance[0]);
    prover.prover_message(&instance[1]);
    let proof = prover.narg_string().to_vec();

    let mut verifier = domain.std_verifier(&proof);
    verifier.public_message(&instance[0]);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), instance[1]);
    assert!(verifier.check_eof().is_ok());
}

#[test]
fn check_eof_reports_remaining_bytes() {
    let instance = [5u32, 6u32];
    let domain = crate::domain_separator!("check eof")
        .without_session()
        .instance(&instance);

    let mut prover = domain.std_prover();
    prover.prover_message(&instance[0]);
    let mut proof = prover.narg_string().to_vec();
    proof.extend_from_slice(&[9u8, 9, 9, 9]);

    let mut verifier = domain.std_verifier(&proof);
    assert_eq!(verifier.prover_message::<u32>().unwrap(), instance[0]);
    assert!(verifier.check_eof().is_err());
}

#[test]
fn verifier_challenge_matches_prover() {
    let instance = [10u32, 11u32];
    let domain = crate::domain_separator!("challenge sync")
        .session(crate::session!("challenge session"))
        .instance(&instance);

    let mut prover = domain.std_prover();
    let challenge: u32 = prover.verifier_message();
    let proof = prover.narg_string().to_vec();

    let mut verifier = domain.std_verifier(&proof);
    let reproduced: u32 = verifier.verifier_message();
    assert_eq!(challenge, reproduced);
}

#[test]
fn domain_separator_accepts_variable_sessions() {
    let instance = [0u8; 0];
    let literal_session = *crate::domain_separator!("variable sessions")
        .session(crate::session!("shared session"))
        .instance(&instance)
        .session
        .value();

    let session_str = "shared session";
    let from_str = *crate::domain_separator!("variable sessions")
        .session(crate::session_id_from_str(session_str))
        .instance(&instance)
        .session
        .value();
    assert_eq!(literal_session, from_str);

    let session_owned = String::from("shared session");
    let from_owned = *crate::domain_separator!("variable sessions")
        .session(crate::session_id_from_str(&session_owned))
        .instance(&instance)
        .session
        .value();
    assert_eq!(literal_session, from_owned);
}

#[test]
fn without_session_distinct_from_real_session() {
    let instance = [0u8; 0];

    let no_sess = crate::domain_separator!("app")
        .without_session()
        .instance(&instance);
    let with_sess = crate::domain_separator!("app")
        .session(crate::session!("production"))
        .instance(&instance);

    let mut a = no_sess.std_prover();
    let mut b = with_sess.std_prover();

    let ca: u32 = a.verifier_message();
    let cb: u32 = b.verifier_message();

    assert_ne!(ca, cb);
}

#[test]
fn different_session_values_diverge() {
    use crate::{DomainSeparator, Encoding};

    struct Ctx(u64);

    impl Encoding for Ctx {
        fn encode(&self) -> impl AsRef<[u8]> {
            self.0.to_le_bytes()
        }
    }

    let instance = [0u8; 0];
    let a = DomainSeparator::new(crate::protocol_id(core::format_args!("p")))
        .session(Ctx(1))
        .instance(&instance);
    let b = DomainSeparator::new(crate::protocol_id(core::format_args!("p")))
        .session(Ctx(2))
        .instance(&instance);

    let mut pa = a.std_prover();
    let mut pb = b.std_prover();

    let ca: u32 = pa.verifier_message();
    let cb: u32 = pb.verifier_message();
    assert_ne!(ca, cb);
}

#[test]
fn protocol_id_zero_pads_ascii() {
    let protocol_id = crate::protocol_id(core::format_args!("sigma-proofs_Shake128_P256"));

    assert_eq!(&protocol_id[..26], b"sigma-proofs_Shake128_P256",);
    assert!(protocol_id[26..].iter().all(|&byte| byte == 0));
}

#[test]
fn session_id_matches_rfc_construction() {
    let mut initial_block = [0u8; 168];
    let domain = b"fiat-shamir/session-id";
    initial_block[..domain.len()].copy_from_slice(domain);

    let mut shake = sha3::Shake128::default();
    shake.update(&initial_block);
    shake.update(b"discrete_logarithm");
    let mut reader = shake.finalize_xof();
    let mut expected_tail = [0u8; 32];
    reader.read(&mut expected_tail);

    let session_id = crate::session_id(core::format_args!("discrete_logarithm"));
    assert!(session_id[..32].iter().all(|&byte| byte == 0));
    assert_eq!(&session_id[32..], &expected_tail);
}

#[test]
fn std_transcript_initialization_matches_manual_shake128() {
    let protocol = crate::protocol_id(core::format_args!("sigma-proofs_Shake128_P256"));
    let session = crate::session_id(core::format_args!("discrete_logarithm"));
    let instance = [42u32, 7u32];

    let domain = crate::DomainSeparator::new(protocol)
        .session(session)
        .instance(&instance);

    let mut prover = domain.std_prover();
    let challenge: [u8; 32] = prover.verifier_message();

    let mut manual = crate::StdHash::from_protocol_id(protocol);
    manual.absorb(&session);
    let encoded_instance = instance.encode();
    manual.absorb(encoded_instance.as_ref());
    let expected = manual.squeeze_array::<32>();

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
    let mut verifier = crate::VerifierState::default_std(&proof);
    assert!(verifier.prover_message::<BadMessage>().is_err());
    assert_eq!(verifier.narg_string, &proof);
    assert!(verifier.check_eof().is_err());
}
