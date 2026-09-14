//! Structure-directed tests of parser totality and transcript binding.
//! Seeds and shrunk counterexamples are reported by proptest. PRs use 256
//! cases per property; the assurance workflow raises PROPTEST_CASES.

use proptest::prelude::*;
use spongefish::{
    derive_session_id,
    instantiations::{Shake128, TurboShake128},
    DuplexSpongeInit, Encoding, LengthPrefixed, NargDeserialize, NargReader, ProverState,
    SessionId, VerificationError, VerifierState,
};

fn lengths() -> impl Strategy<Value = usize> {
    prop_oneof![8 => 0usize..32, 2 => 0usize..512, 1 => Just(usize::MAX), 1 => Just(u32::MAX as usize)]
}

// This transcript tests framing and binding, not a proof-of-knowledge claim:
// each round sends a message followed by an echo of the resulting challenge.
fn prove<H: DuplexSpongeInit<U = u8>>(
    session: &SessionId,
    instance: &[u8; 16],
    messages: &[[u8; 16]],
) -> Vec<u8> {
    let mut prover = ProverState::<H, TurboShake128>::new_with_seed(session, instance, [7; 32]);
    for message in messages {
        prover.prover_message(message);
        let challenge = prover.verifier_message::<[u8; 32]>();
        prover.prover_message(&challenge);
    }
    prover.into_narg_string()
}

fn verify<H: DuplexSpongeInit<U = u8>>(
    session: &SessionId,
    instance: &[u8; 16],
    rounds: usize,
    proof: &[u8],
) -> Result<(), VerificationError> {
    let mut verifier = VerifierState::<H>::new(session, instance, proof);
    for _ in 0..rounds {
        let _message = verifier.prover_message::<[u8; 16]>()?;
        let expected = verifier.verifier_message::<[u8; 32]>();
        let response = verifier.prover_message::<[u8; 32]>()?;
        if response != expected {
            return Err(VerificationError);
        }
    }
    verifier.check_eof()
}

fn binding<H: DuplexSpongeInit<U = u8>>(
    tag: &[u8],
    instance: &[u8; 16],
    messages: &[[u8; 16]],
    offset: usize,
    bit: u8,
) {
    let session = derive_session_id::<H>(tag);
    let proof = prove::<H>(&session, instance, messages);
    assert!(verify::<H>(&session, instance, messages.len(), &proof).is_ok());

    let mut changed = proof.clone();
    let index = offset % changed.len();
    changed[index] ^= 1 << bit;
    assert!(verify::<H>(&session, instance, messages.len(), &changed).is_err());
    assert!(verify::<H>(&session, instance, messages.len(), &proof[..index]).is_err());
    let mut extended = proof.clone();
    extended.push(0);
    assert!(verify::<H>(&session, instance, messages.len(), &extended).is_err());

    let mut other_tag = tag.to_vec();
    other_tag.push(0);
    let other_session = derive_session_id::<H>(&other_tag);
    assert!(verify::<H>(&other_session, instance, messages.len(), &proof).is_err());
    let mut other_instance = *instance;
    other_instance[0] ^= 1;
    assert!(verify::<H>(&session, &other_instance, messages.len(), &proof).is_err());
}

// A deliberately broken element decoder. read_vec must reject it rather than
// looping count times or allocating count elements without consuming input.
struct NoProgress;

impl NargDeserialize for NoProgress {
    fn deserialize_from_narg(_reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
        Ok(Self)
    }
}

proptest! {
    #[test]
    fn reader_matches_a_forward_only_cursor(
        bytes in prop::collection::vec(any::<u8>(), 0..512),
        operations in prop::collection::vec(lengths(), 0..64),
    ) {
        let mut reader = NargReader::new(&bytes);
        let mut offset = 0;
        let mut poisoned = false;
        for length in operations {
            let expected = if poisoned || length > bytes.len() - offset {
                poisoned = true;
                None
            } else {
                let start = offset;
                offset += length;
                Some(&bytes[start..offset])
            };
            prop_assert_eq!(reader.take(length).ok(), expected);
            prop_assert_eq!(reader.is_poisoned(), poisoned);
            prop_assert_eq!(reader.is_empty(), !poisoned && offset == bytes.len());
        }
    }

    #[test]
    fn length_prefixes_bound_parsing_by_available_input(
        count in prop_oneof![0u32..128, any::<u32>()],
        payload in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut bytes = count.to_le_bytes().to_vec();
        bytes.extend_from_slice(&payload);
        let mut reader = NargReader::new(&bytes);
        let result = reader.read::<LengthPrefixed<Vec<u32>>>();
        if u64::from(count) > (payload.len() / 4) as u64 {
            prop_assert!(result.is_err());
            prop_assert!(reader.is_poisoned());
            prop_assert!(reader.take(0).is_err());
        } else {
            let values = result.unwrap().into_inner();
            let count = count as usize;
            let expected: Vec<u32> = payload[..count * 4].chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap())).collect();
            prop_assert_eq!(values, expected);
            prop_assert_eq!(reader.take(payload.len() - count * 4).unwrap(), &payload[count * 4..]);
            prop_assert!(reader.is_empty());
        }
    }

    #[test]
    fn length_prefixed_sequences_round_trip(values in prop::collection::vec(any::<u32>(), 0..128)) {
        let wrapped = LengthPrefixed(&values[..]);
        let bytes = wrapped.encode();
        let mut reader = NargReader::new(bytes.as_ref());
        let parsed = reader.read::<LengthPrefixed<Vec<u32>>>().unwrap();
        prop_assert_eq!(&parsed.into_inner(), &values);
        prop_assert!(reader.is_empty());
    }

    #[test]
    fn zero_width_elements_cannot_drive_unbounded_work(count in lengths()) {
        let mut reader = NargReader::new(b"unconsumed");
        let result = reader.read_vec::<NoProgress>(count);
        prop_assert_eq!(result.is_ok(), count == 0);
        prop_assert_eq!(reader.is_poisoned(), count != 0);
    }

    #[test]
    fn both_suites_bind_every_round_and_reject_corruptions(
        tag in prop::collection::vec(any::<u8>(), 0..64),
        instance in any::<[u8; 16]>(),
        messages in prop::collection::vec(any::<[u8; 16]>(), 1..6),
        offset in any::<usize>(),
        bit in 0u8..8,
    ) {
        binding::<Shake128>(&tag, &instance, &messages, offset, bit);
        binding::<TurboShake128>(&tag, &instance, &messages, offset, bit);
    }

    #[test]
    fn arbitrary_proof_bytes_are_rejected_without_panicking(
        proof in prop::collection::vec(any::<u8>(), 0..300),
        rounds in 1usize..6,
    ) {
        let session = derive_session_id::<TurboShake128>(b"property/arbitrary");
        prop_assert!(verify::<TurboShake128>(&session, &[0; 16], rounds, &proof).is_err());
        prop_assert!(verify::<Shake128>(&session, &[0; 16], rounds, &proof).is_err());
    }

    #[test]
    fn a_codec_cannot_swallow_a_failed_read(
        prefix in prop::collection::vec(any::<u8>(), 0..128),
        suffix in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut proof = prefix.clone();
        proof.extend_from_slice(&suffix);
        let session = derive_session_id::<TurboShake128>(b"property/poison");
        let mut verifier = VerifierState::<TurboShake128>::new(&session, &1u32, &proof);
        let result = verifier.prover_message_as(|reader| {
            reader.take(prefix.len())?;
            // Fail despite a possibly readable suffix, then return success.
            let _ = reader.take(suffix.len() + 1);
            Ok(())
        });
        prop_assert!(result.is_err());
        prop_assert!(verifier.prover_message::<u8>().is_err());
        prop_assert!(verifier.check_eof().is_err());
    }

    #[test]
    fn chunking_preserves_sponge_traces(
        seed in any::<[u8; 32]>(),
        rounds in prop::collection::vec((
            prop::collection::vec(any::<u8>(), 0..400), 0usize..400, 1usize..200,
        ), 0..12),
    ) {
        fn check<H: DuplexSpongeInit<U = u8>>(seed: &[u8; 32], rounds: &[(Vec<u8>, usize, usize)]) {
            let mut whole = H::init(seed);
            let mut split = H::init(seed);
            for (input, length, chunk) in rounds {
                whole.absorb(input);
                split.absorb(&[]);
                for part in input.chunks(*chunk) {
                    split.absorb(part);
                }
                let mut expected = vec![0; *length];
                let mut actual = vec![0; *length];
                whole.squeeze(&mut expected);
                // A zero squeeze can change state; do it on both sides.
                if actual.is_empty() {
                    split.squeeze(&mut actual);
                } else {
                    for part in actual.chunks_mut(*chunk) {
                        split.squeeze(part);
                    }
                }
                assert_eq!(expected, actual);
            }
        }
        check::<Shake128>(&seed, &rounds);
        check::<TurboShake128>(&seed, &rounds);
    }
}
