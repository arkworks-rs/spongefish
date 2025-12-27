use alloc::string::String;

use rand::RngCore;

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
