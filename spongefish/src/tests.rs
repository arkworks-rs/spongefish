use alloc::string::String;

use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::{DuplexSpongeInterface, Encoding, NargDeserialize, VerificationError};

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
fn domain_separator_macro_session_arms_agree_on_domsep() {
    let instance = [0u8; 0];
    let a = crate::domain_separator!("variable sessions"; "shared session").instance(&instance);
    let session_str = "shared session";
    let b = crate::domain_separator!("variable sessions"; session_str).instance(&instance);
    let session_owned = String::from("shared session");
    let c = crate::domain_separator!("variable sessions"; session_owned).instance(&instance);
    let d = crate::domain_separator!("variable sessions"; &session_owned).instance(&instance);
    assert_eq!(a.domsep, b.domsep);
    assert_eq!(a.domsep, c.domsep);
    assert_eq!(a.domsep, d.domsep);
}

/// Empty `session` in [`crate::DomainSeparator::derive`] must not coincide with a real session
/// (upstream tested this via `without_session()` vs `.session(...)`).
#[test]
fn empty_session_distinct_from_nonempty_session() {
    let instance = [0u8; 0];
    let proto = crate::protocol_label(core::format_args!("app"));
    let no_sess = crate::DomainSeparator::derive(
        proto.as_slice(),
        crate::DOMAIN_SEPARATOR_MACRO_SPONGE_INFO,
        &[],
    )
    .instance(&instance);
    let with_sess = crate::domain_separator!("app"; "production").instance(&instance);

    assert_ne!(no_sess.domsep, with_sess.domsep);

    let mut a = no_sess.std_prover();
    let mut b = with_sess.std_prover();
    assert_ne!(a.verifier_message::<u32>(), b.verifier_message::<u32>());
}

#[test]
fn different_derive_session_bytes_diverge() {
    use crate::DomainSeparator;

    struct Ctx(u64);

    impl Encoding for Ctx {
        fn encode(&self) -> impl AsRef<[u8]> {
            self.0.to_le_bytes()
        }
    }

    let instance = [0u8; 0];
    let proto = crate::protocol_id(core::format_args!("p"));
    let a = DomainSeparator::derive(
        proto.as_slice(),
        crate::DOMAIN_SEPARATOR_MACRO_SPONGE_INFO,
        Ctx(1).encode().as_ref(),
    )
    .instance(&instance);
    let b = DomainSeparator::derive(
        proto.as_slice(),
        crate::DOMAIN_SEPARATOR_MACRO_SPONGE_INFO,
        Ctx(2).encode().as_ref(),
    )
    .instance(&instance);

    let mut pa = a.std_prover();
    let mut pb = b.std_prover();
    assert_ne!(
        pa.verifier_message::<u32>(),
        pb.verifier_message::<u32>()
    );
}

#[test]
fn same_session_encoding_same_challenge() {
    struct Ctx(String);

    impl Encoding for Ctx {
        fn encode(&self) -> impl AsRef<[u8]> {
            self.0.as_str().encode()
        }
    }

    let instance = [0u8; 0];
    let proto = crate::protocol_label(core::format_args!("borrowed session"));
    let b1 = Ctx(String::from("borrowed-session"));
    let b2 = Ctx(String::from("borrowed-session"));
    let dom1 = crate::DomainSeparator::derive(
        proto.as_slice(),
        crate::DOMAIN_SEPARATOR_MACRO_SPONGE_INFO,
        b1.encode().as_ref(),
    )
    .instance(&instance);
    let dom2 = crate::DomainSeparator::derive(
        proto.as_slice(),
        crate::DOMAIN_SEPARATOR_MACRO_SPONGE_INFO,
        b2.encode().as_ref(),
    )
    .instance(&instance);

    assert_eq!(dom1.domsep, dom2.domsep);
    let c1: u64 = dom1.std_prover().verifier_message();
    let c2: u64 = dom2.std_prover().verifier_message();
    assert_eq!(c1, c2);
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

    let domain = crate::DomainSeparator::derive(
        protocol.as_slice(),
        crate::DOMAIN_SEPARATOR_MACRO_SPONGE_INFO,
        session.as_slice(),
    )
    .instance(&instance);

    let mut prover = domain.std_prover();
    let challenge: [u8; 32] = prover.verifier_message();

    let domsep = crate::derive_domain_digest(
        protocol.as_slice(),
        crate::DOMAIN_SEPARATOR_MACRO_SPONGE_INFO,
        session.as_slice(),
    );
    let mut manual = crate::StdHash::from_protocol_id(domsep);
    let encoded_instance = instance.encode();
    manual.absorb(encoded_instance.as_ref());
    let expected = manual.squeeze_array::<32>();

    assert_eq!(challenge, expected);
}

#[test]
fn derive_matches_prefix_builder_and_differs_on_inputs() {
    let p = b"p";
    let i = b"i";
    let s = b"s";
    let d = crate::derive_domain_digest(p, i, s);
    let from_builder = crate::DomainSeparatorPrefix::new(p, i).with_session::<[u32; 0]>(s);
    assert_eq!(from_builder.domsep, d);

    let d2 = crate::derive_domain_digest(p, i, b"t");
    assert_ne!(d, d2);
}

#[cfg(feature = "keccak")]
#[test]
fn derived_duplex_keccak_challenge_matches() {
    use crate::instantiations::Keccak;

    let instance = [3u32, 14u32];
    let dom = crate::DomainSeparator::derive(b"proto", b"sponge", b"sess").instance(&instance);

    let mut p = dom.to_prover(Keccak::default());
    let challenge: u32 = p.verifier_message();
    let proof = p.narg_string().to_vec();

    let mut v = dom.to_verifier(Keccak::default(), &proof);
    assert_eq!(v.verifier_message::<u32>(), challenge);
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

#[test]
fn str_encoding_prefixes_utf8_with_le_u32_length() {
    let encoded = "hello".encode();
    assert_eq!(encoded.as_ref(), b"\x05\x00\x00\x00hello");

    let encoded_utf8 = "hé".encode();
    assert_eq!(encoded_utf8.as_ref(), b"\x03\x00\x00\x00h\xc3\xa9");
}
