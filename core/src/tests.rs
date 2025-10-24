use rand::RngCore;

use crate::{
    duplex_sponge::legacy::DigestBridge, instantiations::hash::Hash, keccak::Keccak,
    BytesToUnitDeserialize, BytesToUnitSerialize, CommonUnitToBytes, DomainSeparator,
    DuplexSpongeInterface, HashStateWithInstructions, ProverState, UnitToBytes,
};

#[cfg(feature = "sha2")]
type Sha2 = Hash<sha2::Sha256>;
#[cfg(feature = "blake2")]
type Blake2b512 = Hash<blake2::Blake2b512>;
#[cfg(feature = "blake2")]
type Blake2s256 = Hash<blake2::Blake2s256>;

/// How should a protocol without actual IO be handled?
#[test]
fn test_domain_separator() {
    // test that the byte separator is always added
    let domain_separator = DomainSeparator::<Keccak>::new("example.com");
    assert!(domain_separator.as_bytes().starts_with(b"example.com"));
}

/// Test ProverState's rng is not doing completely stupid things.
#[test]
fn test_prover_rng_basic() {
    let domain_separator = DomainSeparator::<Keccak>::new("example.com");
    let mut prover_state = domain_separator.to_prover_state();
    let rng = prover_state.rng();

    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    let random_u32 = rng.next_u32();
    let random_u64 = rng.next_u64();
    assert_ne!(random_bytes, [0u8; 32]);
    assert_ne!(random_u32, 0);
    assert_ne!(random_u64, 0);
    assert!(random_bytes.iter().any(|&x| x != random_bytes[0]));
}

/// Test adding of public bytes and non-public elements to the transcript.
#[test]
fn test_prover_bytewriter() {
    let domain_separator = DomainSeparator::<Keccak>::new("example.com").absorb(1, "🥕");
    let mut prover_state = domain_separator.to_prover_state();
    assert!(prover_state.add_bytes(&[0u8]).is_ok());
    assert!(prover_state.add_bytes(&[1u8]).is_err());
    assert_eq!(
        prover_state.narg_string(),
        b"\0",
        "Protocol Transcript survives errors"
    );

    let mut prover_state = domain_separator.to_prover_state();
    assert!(prover_state.public_bytes(&[0u8]).is_ok());
    assert_eq!(prover_state.narg_string(), b"");
}

/// A protocol flow that does not match the DomainSeparator should fail.
#[test]
fn test_invalid_domsep_sequence() {
    let domain_separator = DomainSeparator::new("example.com")
        .absorb(3, "")
        .squeeze(1, "");
    let mut verifier_state = HashStateWithInstructions::<Keccak>::new(&domain_separator);
    assert!(verifier_state.squeeze(&mut [0u8; 16]).is_err());
}

/// Challenges from the same transcript should be equal.
#[test]
fn test_deterministic() {
    let domain_separator = DomainSeparator::new("example.com")
        .absorb(3, "elt")
        .squeeze(16, "another_elt");
    let mut first_sponge = HashStateWithInstructions::<Keccak>::new(&domain_separator);
    let mut second_sponge = HashStateWithInstructions::<Keccak>::new(&domain_separator);

    let mut first = [0u8; 16];
    let mut second = [0u8; 16];

    first_sponge.absorb(b"123").unwrap();
    second_sponge.absorb(b"123").unwrap();

    first_sponge.squeeze(&mut first).unwrap();
    second_sponge.squeeze(&mut second).unwrap();
    assert_eq!(first, second);
}

/// Basic scatistical test to check that the squeezed output looks random.
#[test]
fn test_statistics() {
    let domain_separator = DomainSeparator::new("example.com")
        .absorb(4, "statement")
        .ratchet()
        .squeeze(2048, "gee");
    let mut verifier_state = HashStateWithInstructions::<Keccak>::new(&domain_separator);
    verifier_state.absorb(b"seed").unwrap();
    verifier_state.ratchet().unwrap();
    let mut output = [0u8; 2048];
    verifier_state.squeeze(&mut output).unwrap();

    let frequencies = (0u8..=255)
        .map(|i| output.iter().filter(|&&x| x == i).count())
        .collect::<Vec<_>>();
    // each element should appear roughly 8 times on average. Checking we're not too far from that.
    assert!(frequencies.iter().all(|&x| x < 32 && x > 0));
}

#[test]
fn test_transcript_readwrite() {
    let domain_separator = DomainSeparator::<Keccak>::new("domain separator")
        .absorb(10, "hello")
        .squeeze(10, "world");

    let mut prover_state = domain_separator.to_prover_state();
    prover_state
        .add_units(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        .unwrap();
    let prover_challenges = prover_state.challenge_bytes::<10>().unwrap();
    let transcript = prover_state.narg_string();

    let mut verifier_state = domain_separator.to_verifier_state(transcript);
    let mut input = [0u8; 5];
    verifier_state.fill_next_units(&mut input).unwrap();
    assert_eq!(input, [0, 1, 2, 3, 4]);
    verifier_state.fill_next_units(&mut input).unwrap();
    assert_eq!(input, [5, 6, 7, 8, 9]);
    let verifier_challenges = verifier_state.challenge_bytes::<10>().unwrap();
    assert_eq!(verifier_challenges, prover_challenges);
}

/// An IO that is not fully finished should fail.
#[test]
#[should_panic]
fn test_incomplete_domsep() {
    let domain_separator = DomainSeparator::<Keccak>::new("domain separator")
        .absorb(10, "hello")
        .squeeze(1, "nop");

    let mut prover_state = domain_separator.to_prover_state();
    prover_state
        .add_units(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        .unwrap();
    prover_state.fill_challenge_bytes(&mut [0u8; 10]).unwrap();
}

/// The user should respect the domain separator even with empty length.
#[test]
fn test_prover_empty_absorb() {
    let domain_separator = DomainSeparator::<Keccak>::new("domain separator")
        .absorb(1, "in")
        .squeeze(1, "something");

    assert!(domain_separator
        .to_prover_state()
        .fill_challenge_bytes(&mut [0u8; 1])
        .is_err());
    assert!(domain_separator
        .to_verifier_state(b"")
        .next_bytes::<1>()
        .is_err());
}

/// Absorbs and squeeze over byte-Units should be streamable.
fn test_streaming_absorb_and_squeeze<H: DuplexSpongeInterface>()
where
    ProverState<H>: BytesToUnitSerialize + UnitToBytes,
{
    let bytes = b"yellow submarine";

    let domain_separator = DomainSeparator::<H>::new("domain separator")
        .absorb(16, "some bytes")
        .squeeze(16, "control challenge")
        .absorb(1, "level 2: use this as a prng stream")
        .squeeze(1024, "that's a long challenge");

    let mut prover_state = domain_separator.to_prover_state();
    prover_state.add_bytes(bytes).unwrap();
    let control_chal = prover_state.challenge_bytes::<16>().unwrap();
    let control_transcript = prover_state.narg_string();

    let mut stream_prover_state = domain_separator.to_prover_state();
    stream_prover_state.add_bytes(&bytes[..10]).unwrap();
    stream_prover_state.add_bytes(&bytes[10..]).unwrap();
    let first_chal = stream_prover_state.challenge_bytes::<8>().unwrap();
    let second_chal = stream_prover_state.challenge_bytes::<8>().unwrap();
    let transcript = stream_prover_state.narg_string();

    assert_eq!(transcript, control_transcript);
    assert_eq!(&first_chal[..], &control_chal[..8]);
    assert_eq!(&second_chal[..], &control_chal[8..]);

    prover_state.add_bytes(&[0x42]).unwrap();
    stream_prover_state.add_bytes(&[0x42]).unwrap();

    let control_chal = prover_state.challenge_bytes::<1024>().unwrap();
    for control_chunk in control_chal.chunks(16) {
        let chunk = stream_prover_state.challenge_bytes::<16>().unwrap();
        assert_eq!(control_chunk, &chunk[..]);
    }
}

#[cfg(feature = "sha2")]
#[test]
fn test_streaming_sha2() {
    test_streaming_absorb_and_squeeze::<Sha2>();
}

#[cfg(feature = "blake2")]
#[test]
fn test_streaming_blake2() {
    test_streaming_absorb_and_squeeze::<Blake2b512>();
    test_streaming_absorb_and_squeeze::<Blake2s256>();
}

#[test]
fn test_streaming_keccak() {
    test_streaming_absorb_and_squeeze::<Keccak>();
}

use std::{cell::RefCell, rc::Rc};

use super::*;

#[derive(Default, Clone)]
pub struct DummySponge {
    pub absorbed: Rc<RefCell<Vec<u8>>>,
    pub squeezed: Rc<RefCell<Vec<u8>>>,
    pub ratcheted: Rc<RefCell<bool>>,
}

impl zeroize::Zeroize for DummySponge {
    fn zeroize(&mut self) {
        self.absorbed.borrow_mut().clear();
        self.squeezed.borrow_mut().clear();
        *self.ratcheted.borrow_mut() = false;
    }
}

impl DummySponge {
    fn new_inner() -> Self {
        Self {
            absorbed: Rc::new(RefCell::new(Vec::new())),
            squeezed: Rc::new(RefCell::new(Vec::new())),
            ratcheted: Rc::new(RefCell::new(false)),
        }
    }
}

impl DuplexSpongeInterface<u8> for DummySponge {
    fn new() -> Self {
        Self::new_inner()
    }

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        self.absorbed.borrow_mut().extend_from_slice(input);
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        for (i, byte) in output.iter_mut().enumerate() {
            *byte = i as u8;
        }
        self.squeezed.borrow_mut().extend_from_slice(output);
        self
    }

    fn ratchet(&mut self) -> &mut Self {
        *self.ratcheted.borrow_mut() = true;
        self
    }
}

#[test]
fn test_new_verifier_state_constructs_correctly() {
    let ds = DomainSeparator::<DummySponge>::new("test");
    let transcript = b"abc";
    let vs = VerifierState::<DummySponge>::new(&ds, transcript);
    assert_eq!(vs.narg_string, b"abc");
}

#[test]
fn test_fill_next_units_reads_and_absorbs() {
    let ds = DomainSeparator::<DummySponge>::new("x").absorb(3, "input");
    let mut vs = VerifierState::<DummySponge>::new(&ds, b"abc");
    let mut buf = [0u8; 3];
    let res = vs.fill_next_units(&mut buf);
    assert!(res.is_ok());
    assert_eq!(buf, *b"abc");
    assert_eq!(*vs.hash_state.ds().absorbed.borrow(), b"abc");
}

#[test]
fn test_fill_next_units_with_insufficient_data_errors() {
    let ds = DomainSeparator::<DummySponge>::new("x").absorb(4, "fail");
    let mut vs = VerifierState::<DummySponge>::new(&ds, b"xy");
    let mut buf = [0u8; 4];
    let res = vs.fill_next_units(&mut buf);
    assert!(res.is_err());
}

#[test]
fn test_ratcheting_success() {
    let ds = DomainSeparator::<DummySponge>::new("x").ratchet();
    let mut vs = VerifierState::<DummySponge>::new(&ds, &[]);
    assert!(vs.ratchet().is_ok());
    assert!(*vs.hash_state.ds().ratcheted.borrow());
}

#[test]
fn test_ratcheting_wrong_op_errors() {
    let ds = DomainSeparator::<DummySponge>::new("x").absorb(1, "wrong");
    let mut vs = VerifierState::<DummySponge>::new(&ds, b"z");
    assert!(vs.ratchet().is_err());
}

#[test]
fn test_unit_transcript_public_units() {
    let ds = DomainSeparator::<DummySponge>::new("x").absorb(2, "public");
    let mut vs = VerifierState::<DummySponge>::new(&ds, b"..");
    assert!(vs.public_units(&[1, 2]).is_ok());
    assert_eq!(*vs.hash_state.ds().absorbed.borrow(), &[1, 2]);
}

#[test]
fn test_unit_transcript_fill_challenge_units() {
    let ds = DomainSeparator::<DummySponge>::new("x").squeeze(4, "c");
    let mut vs = VerifierState::<DummySponge>::new(&ds, b"abcd");
    let mut out = [0u8; 4];
    assert!(vs.fill_challenge_units(&mut out).is_ok());
    assert_eq!(out, [0, 1, 2, 3]);
}

#[test]
fn test_fill_next_bytes_impl() {
    let ds = DomainSeparator::<DummySponge>::new("x").absorb(3, "byte");
    let mut vs = VerifierState::<DummySponge>::new(&ds, b"xyz");
    let mut out = [0u8; 3];
    assert!(vs.fill_next_bytes(&mut out).is_ok());
    assert_eq!(out, *b"xyz");
}

#[test]
fn test_hint_bytes_verifier_valid_hint() {
    // Domain separator commits to a hint
    let domsep: DomainSeparator<DummySponge> = DomainSeparator::new("valid").hint("hint");

    let mut prover = domsep.to_prover_state();

    let hint = b"abc123";
    prover.hint_bytes(hint).unwrap();

    let narg = prover.narg_string();

    let mut verifier = domsep.to_verifier_state(narg);
    let result = verifier.hint_bytes().unwrap();
    assert_eq!(result, hint);
}

#[test]
fn test_hint_bytes_verifier_empty_hint() {
    // Commit to a hint instruction
    let domsep: DomainSeparator<DummySponge> = DomainSeparator::new("empty").hint("hint");

    let mut prover = domsep.to_prover_state();

    let hint = b"";
    prover.hint_bytes(hint).unwrap();

    let narg = prover.narg_string();

    let mut verifier = domsep.to_verifier_state(narg);
    let result = verifier.hint_bytes().unwrap();
    assert_eq!(result, b"");
}

#[test]
fn test_hint_bytes_verifier_no_hint_op() {
    // No hint instruction in domain separator
    let domsep: DomainSeparator<DummySponge> = DomainSeparator::new("nohint");

    // Manually construct a hint buffer (length = 6, followed by bytes)
    let mut narg = vec![6, 0, 0, 0]; // length prefix for 6
    narg.extend_from_slice(b"abc123");

    let mut verifier = domsep.to_verifier_state(&narg);

    assert!(verifier.hint_bytes().is_err());
}

#[test]
fn test_hint_bytes_verifier_length_prefix_too_short() {
    // Valid hint domain separator
    let domsep: DomainSeparator<DummySponge> = DomainSeparator::new("short").hint("hint");

    // Provide only 3 bytes, which is not enough for a u32 length
    let narg = &[1, 2, 3]; // less than 4 bytes

    let mut verifier = domsep.to_verifier_state(narg);

    let err = verifier.hint_bytes().unwrap_err();
    assert!(
        format!("{err}").contains("Insufficient transcript remaining for hint"),
        "Expected error for short prefix, got: {err}"
    );
}

#[test]
fn test_hint_bytes_verifier_declared_hint_too_long() {
    // Valid hint domain separator
    let domsep: DomainSeparator<DummySponge> = DomainSeparator::new("loverflow").hint("hint");

    // Prefix says "5 bytes", but we only supply 2
    let narg = &[5, 0, 0, 0, b'a', b'b'];

    let mut verifier = domsep.to_verifier_state(narg);

    let err = verifier.hint_bytes().unwrap_err();
    assert!(
        format!("{err}").contains("Insufficient transcript remaining"),
        "Expected error for hint length > actual NARG bytes, got: {err}"
    );
}

#[cfg(test)]
mod prover {
    use super::*;

    #[test]
    fn test_prover_state_add_units_and_rng_differs() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(4, "data");
        let mut pstate = ProverState::from(&domsep);

        pstate.add_bytes(&[1, 2, 3, 4]).unwrap();

        let mut buf = [0u8; 8];
        pstate.rng().fill_bytes(&mut buf);
        assert_ne!(buf, [0; 8]);
    }

    #[test]
    fn test_prover_state_public_units_does_not_affect_narg() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(4, "data");
        let mut pstate = ProverState::from(&domsep);

        pstate.public_units(&[1, 2, 3, 4]).unwrap();
        assert_eq!(pstate.narg_string(), b"");
    }

    #[test]
    fn test_prover_state_ratcheting_changes_rng_output() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").ratchet();
        let mut pstate = ProverState::from(&domsep);

        let mut buf1 = [0u8; 4];
        pstate.rng().fill_bytes(&mut buf1);

        pstate.ratchet().unwrap();

        let mut buf2 = [0u8; 4];
        pstate.rng().fill_bytes(&mut buf2);

        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_add_units_appends_to_narg_string() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(3, "msg");
        let mut pstate = ProverState::from(&domsep);
        let input = [42, 43, 44];

        assert!(pstate.add_units(&input).is_ok());
        assert_eq!(pstate.narg_string(), &input);
    }

    #[test]
    fn test_add_units_too_many_elements_should_error() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(2, "short");
        let mut pstate = ProverState::from(&domsep);

        let result = pstate.add_units(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ratchet_works_when_expected() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").ratchet();
        let mut pstate = ProverState::from(&domsep);
        assert!(pstate.ratchet().is_ok());
    }

    #[test]
    fn test_ratchet_fails_when_not_expected() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(1, "bad");
        let mut pstate = ProverState::from(&domsep);
        assert!(pstate.ratchet().is_err());
    }

    #[test]
    fn test_public_units_does_not_update_transcript() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").absorb(2, "p");
        let mut pstate = ProverState::from(&domsep);
        let _ = pstate.public_units(&[0xaa, 0xbb]);

        assert_eq!(pstate.narg_string(), b"");
    }

    #[test]
    fn test_fill_challenge_units() {
        let domsep = DomainSeparator::<DefaultHash>::new("test").squeeze(8, "ch");
        let mut pstate = ProverState::from(&domsep);

        let mut out = [0u8; 8];
        let _ = pstate.fill_challenge_units(&mut out);
        assert_ne!(out, [0; 8]);
    }

    #[test]
    fn test_rng_entropy_changes_with_transcript() {
        let domsep = DomainSeparator::<DefaultHash>::new("t").absorb(3, "init");
        let mut p1 = ProverState::from(&domsep);
        let mut p2 = ProverState::from(&domsep);

        let mut a = [0u8; 16];
        let mut b = [0u8; 16];

        p1.rng().fill_bytes(&mut a);
        p2.add_units(&[1, 2, 3]).unwrap();
        p2.rng().fill_bytes(&mut b);

        assert_ne!(a, b);
    }

    #[test]
    fn test_add_units_multiple_accumulates() {
        let domsep = DomainSeparator::<DefaultHash>::new("t")
            .absorb(2, "a")
            .absorb(3, "b");
        let mut p = ProverState::from(&domsep);

        p.add_units(&[10, 11]).unwrap();
        p.add_units(&[20, 21, 22]).unwrap();

        assert_eq!(p.narg_string(), &[10, 11, 20, 21, 22]);
    }

    #[test]
    fn test_narg_string_round_trip_check() {
        let domsep = DomainSeparator::<DefaultHash>::new("t").absorb(5, "data");
        let mut p = ProverState::from(&domsep);

        let msg = b"zkp42";
        p.add_units(msg).unwrap();

        let encoded = p.narg_string();
        assert_eq!(encoded, msg);
    }

    #[test]
    fn test_hint_bytes_appends_hint_length_and_data() {
        let domsep: DomainSeparator<DefaultHash> =
            DomainSeparator::new("hint_test").hint("proof_hint");
        let mut prover = domsep.to_prover_state();

        let hint = b"abc123";
        prover.hint_bytes(hint).unwrap();

        // Explanation:
        // - `hint` is "abc123", which has 6 bytes.
        // - The protocol encodes this as a 4-byte *little-endian* length prefix: 6 = 0x00000006 → [6, 0, 0, 0]
        // - Then it appends the hint bytes: b"abc123"
        // - So the full expected value is:
        let expected = [6, 0, 0, 0, b'a', b'b', b'c', b'1', b'2', b'3'];

        assert_eq!(prover.narg_string(), &expected);
    }

    #[test]
    fn test_hint_bytes_empty_hint_is_encoded_correctly() {
        let domsep: DomainSeparator<DefaultHash> = DomainSeparator::new("empty_hint").hint("empty");
        let mut prover = domsep.to_prover_state();

        prover.hint_bytes(b"").unwrap();

        // Length = 0 encoded as 4 zero bytes
        assert_eq!(prover.narg_string(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_hint_bytes_fails_if_hint_op_missing() {
        let domsep: DomainSeparator<DefaultHash> = DomainSeparator::new("no_hint");
        let mut prover = domsep.to_prover_state();

        // DomainSeparator contains no hint operation
        let result = prover.hint_bytes(b"some_hint");
        assert!(
            result.is_err(),
            "Should error if no hint op in domain separator"
        );
    }

    #[test]
    fn test_hint_bytes_is_deterministic() {
        let domsep: DomainSeparator<DefaultHash> = DomainSeparator::new("det_hint").hint("same");

        let hint = b"zkproof_hint";
        let mut prover1 = domsep.to_prover_state();
        let mut prover2 = domsep.to_prover_state();

        prover1.hint_bytes(hint).unwrap();
        prover2.hint_bytes(hint).unwrap();

        assert_eq!(
            prover1.narg_string(),
            prover2.narg_string(),
            "Encoding should be deterministic"
        );
    }
}

#[cfg(test)]
mod duplex_sponge {
    use super::*;
    use crate::keccak::Keccak;

    #[test]
    fn test_squeeze_zero_after_behavior() {
        let mut sponge = Keccak::new();
        let mut output = [0u8; 64];

        let input = b"Hello, World!";
        sponge.squeeze(&mut [0u8; 0]);
        sponge.absorb(input);
        sponge.squeeze(&mut output);

        assert!(output.iter().any(|u| *u != 0));
    }

    #[test]
    fn test_associativity_of_absorb() {
        let expected_output =
            hex::decode("7dfada182d6191e106ce287c2262a443ce2fb695c7cc5037a46626e88889af58")
                .unwrap();
        let mut sponge1 = Keccak::new();
        sponge1.absorb(b"hello world");
        let mut out1 = [0u8; 32];
        sponge1.squeeze(&mut out1);

        let mut sponge2 = Keccak::new();
        sponge2.absorb(b"hello");
        sponge2.absorb(b" world");
        let mut out2 = [0u8; 32];
        sponge2.squeeze(&mut out2);

        assert_eq!(out1.to_vec(), expected_output);
        assert_eq!(out2.to_vec(), expected_output);
    }

    #[test]
    fn test_tag_affects_output() {
        let mut sponge1 = Keccak::new();
        let mut sponge2 = Keccak::new();

        let mut output1 = [0u8; 32];
        sponge1.absorb(b"input1");
        sponge1.squeeze(&mut output1);

        let mut output2 = [0u8; 32];
        sponge2.absorb(b"input2");
        sponge2.squeeze(&mut output2);

        assert_ne!(output1, output2)
    }

    #[test]
    fn test_zeroize_clears_memory() {
        use core::ptr;

        use zeroize::Zeroize;

        // Create a sponge with sensitive data
        let mut sponge = Keccak::new();
        sponge.absorb(b"secret data that must be cleared");

        // Get a pointer to the internal state before zeroization
        let state_ptr = sponge.permutation.as_ref().as_ptr();
        let state_len = sponge.permutation.as_ref().len();

        // Verify state contains non-zero data
        let has_nonzero_before =
            unsafe { (0..state_len).any(|i| ptr::read(state_ptr.add(i)) != 0) };
        assert!(
            has_nonzero_before,
            "State should contain non-zero data before zeroization"
        );

        sponge.zeroize();

        // Verify all bytes in the state are now zero
        let all_zero_after = unsafe { (0..state_len).all(|i| ptr::read(state_ptr.add(i)) == 0) };
        assert!(
            all_zero_after,
            "State should be completely zeroed after zeroization"
        );

        // Also verify the position counters are zeroed
        assert_eq!(sponge.absorb_pos, 0);
        assert_eq!(sponge.squeeze_pos, 0);
    }
}
