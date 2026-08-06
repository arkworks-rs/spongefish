use shake::{ExtendableOutput, Update, XofReader};

use crate::{
    derive_session_id, DuplexSpongeInterface, Encoding, LengthPrefixed, NargDeserialize,
    NargSerialize, ProverState, StdHash, VerificationError, VerificationResult, VerifierState,
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
    c.mix_entropy(b"extra");
    let mut rc = [0u8; 32];
    c.rng().fill_bytes(&mut rc);
    assert_ne!(ra, rc);
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
fn closure_codecs_round_trip() {
    struct Foreign(u64);

    let instance = [9u32];
    let session_id = test_session_id(b"closure codecs");

    let value = Foreign(0xdead_beef);
    let mut prover = ProverState::<StdHash>::new(&session_id, &instance);
    prover.prover_message_as(&value, |v| v.0.to_le_bytes());
    let prover_challenge: [u8; 16] = prover.verifier_message();
    let proof = prover.narg_string().to_vec();

    let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, &proof);
    let read = verifier
        .prover_message_as(|buf| {
            if buf.len() < 8 {
                return Err(VerificationError);
            }
            let value = u64::from_le_bytes(buf[..8].try_into().unwrap());
            *buf = &buf[8..];
            Ok(Foreign(value))
        })
        .unwrap();
    assert_eq!(read.0, value.0);
    let verifier_challenge: [u8; 16] = verifier.verifier_message();
    assert_eq!(prover_challenge, verifier_challenge);
    assert!(verifier.check_eof().is_ok());
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

mod word_sponge {
    use crate::duplex_sponge::{DuplexSponge, Permutation};

    /// Toy ARX permutation over four `u64` words. Deterministic mixing with no
    /// security claim; it exists to exercise the generic-alphabet
    /// (`H::U != u8`) API surface.
    #[derive(Clone, Default)]
    pub struct ToyPermutation;

    impl Permutation<4> for ToyPermutation {
        type U = u64;

        fn permute(&self, state: &[u64; 4]) -> [u64; 4] {
            let mut s = *state;
            for _ in 0..8 {
                s[0] = s[0].wrapping_add(s[1]).rotate_left(13) ^ s[2];
                s[1] = s[1].wrapping_add(s[2]).rotate_left(29) ^ s[3];
                s[2] = s[2].wrapping_add(s[3]).rotate_left(43) ^ s[0];
                s[3] = s[3].wrapping_add(s[0]).rotate_left(7) ^ s[1];
            }
            s
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
    let proof = prover.narg_string().to_vec();

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
    static ELSEWHERE: [u8; 2] = [1, 2];

    let proof = [7u8, 8, 9];
    let session_id = test_session_id(b"with rollback");
    let mut verifier = VerifierState::<StdHash>::new(&session_id, b"instance", &proof);

    // A failing deserializer leaves the cursor unchanged and absorbs nothing.
    let result: VerificationResult<u64> = verifier.prover_message_with(
        |buf| {
            *buf = &buf[1..];
            Err(VerificationError)
        },
        |v: &u64| v.to_le_bytes(),
    );
    assert!(result.is_err());
    assert_eq!(verifier.narg_string, &proof);

    // A deserializer that repoints its cursor off the NARG string is rejected.
    let result: VerificationResult<u64> = verifier.prover_message_with(
        |buf| {
            *buf = &ELSEWHERE;
            Ok(3)
        },
        |v: &u64| v.to_le_bytes(),
    );
    assert!(result.is_err());
    assert_eq!(verifier.narg_string, &proof);
}

#[test]
fn closure_batch_helpers_round_trip() {
    let instance = [1u32];
    let session_id = test_session_id(b"closure batch");
    let points: [[u8; 4]; 3] = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]];

    let mut prover = ProverState::<StdHash>::new(&session_id, &instance);
    prover.prover_messages_as(&points, |point| *point);
    let proof = prover.narg_string().to_vec();
    assert_eq!(proof, points.concat());
    let prover_challenge: [u8; 16] = prover.verifier_message();

    let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, &proof);
    let read_back = verifier
        .prover_messages_vec_as(points.len(), |buf| {
            if buf.len() < 4 {
                return Err(VerificationError);
            }
            let point: [u8; 4] = buf[..4].try_into().unwrap();
            *buf = &buf[4..];
            Ok(point)
        })
        .unwrap();
    assert_eq!(read_back, points);
    let verifier_challenge: [u8; 16] = verifier.verifier_message();
    assert_eq!(prover_challenge, verifier_challenge);
    assert!(verifier.check_eof().is_ok());
}

#[test]
fn length_prefixed_round_trip() {
    let instance = [9u32];
    let session_id = test_session_id(b"length prefixed");
    let values = alloc::vec![10u32, 20, 30];

    let mut prover = ProverState::<StdHash>::new(&session_id, &instance);
    prover.prover_message(&LengthPrefixed(&values[..]));
    let proof = prover.narg_string().to_vec();
    let prover_challenge: [u8; 16] = prover.verifier_message();

    let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, &proof);
    let LengthPrefixed(read_back): LengthPrefixed<alloc::vec::Vec<u32>> =
        verifier.prover_message().unwrap();
    assert_eq!(read_back, values);
    let verifier_challenge: [u8; 16] = verifier.verifier_message();
    assert_eq!(prover_challenge, verifier_challenge);
    assert!(verifier.check_eof().is_ok());

    // A tampered NARG string either fails to parse or produces a different verifier message.
    let mut tampered = proof;
    tampered[0] ^= 1;
    let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, &tampered);
    if verifier
        .prover_message::<LengthPrefixed<alloc::vec::Vec<u32>>>()
        .is_ok()
    {
        let tampered_challenge: [u8; 16] = verifier.verifier_message();
        assert_ne!(prover_challenge, tampered_challenge);
    }
}
