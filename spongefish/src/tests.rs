use alloc::string::String;

use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::{DuplexSpongeInterface, Encoding};

#[test]
fn prover_rng_emits_entropy() {
    let instance = [42u32, 7u32];
    let domain = crate::domain_separator!("rng test"; "rng session").instance(&instance);

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
    let domain = crate::domain_separator!("round trip").instance(&instance);

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
    let domain = crate::domain_separator!("check eof").instance(&instance);

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
    let domain =
        crate::domain_separator!("challenge sync"; "challenge session").instance(&instance);

    let mut prover = domain.std_prover();
    let challenge: u32 = prover.verifier_message();
    let proof = prover.narg_string().to_vec();

    let mut verifier = domain.std_verifier(&proof);
    let reproduced: u32 = verifier.verifier_message();
    assert_eq!(challenge, reproduced);
}

#[cfg(feature = "sha2")]
#[test]
fn digest_ratchet_keeps_squeezed_state() {
    let mut first = crate::instantiations::SHA256::default();
    first.absorb(b"first transcript");
    let _ = first.squeeze_array::<17>();
    first.ratchet();
    let out1 = first.squeeze_array::<32>();

    let mut second = crate::instantiations::SHA256::default();
    second.absorb(b"second transcript");
    let _ = second.squeeze_array::<17>();
    second.ratchet();
    let out2 = second.squeeze_array::<32>();

    assert_ne!(out1, out2);
}

#[test]
fn stdhash_ratchet_keeps_squeezed_state() {
    let protocol = crate::protocol_id(core::format_args!("ratchet test"));

    let mut first = crate::StdHash::from_protocol_id(protocol);
    first.absorb(b"first transcript");
    let _ = first.squeeze_array::<17>();
    first.ratchet();
    let out1 = first.squeeze_array::<32>();

    let mut second = crate::StdHash::from_protocol_id(protocol);
    second.absorb(b"second transcript");
    let _ = second.squeeze_array::<17>();
    second.ratchet();
    let out2 = second.squeeze_array::<32>();

    assert_ne!(out1, out2);
}

#[test]
fn domain_separator_accepts_variable_sessions() {
    let instance = [0u8; 0];
    let literal_session = crate::domain_separator!("variable sessions"; "shared session")
        .instance(&instance)
        .session
        .expect("literal session missing");
    let session_str = "shared session";
    let from_str = crate::domain_separator!("variable sessions"; session_str)
        .instance(&instance)
        .session
        .expect("string session missing");
    assert_eq!(literal_session, from_str);

    let session_owned = String::from("shared session");
    let from_owned = crate::domain_separator!("variable sessions"; session_owned)
        .instance(&instance)
        .session
        .expect("owned session missing");
    assert_eq!(literal_session, from_owned);

    let from_owned_ref = crate::domain_separator!("variable sessions"; &session_owned)
        .instance(&instance)
        .session
        .expect("reference session missing");
    assert_eq!(literal_session, from_owned_ref);
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
