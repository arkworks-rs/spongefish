use spongefish::{DuplexSponge, DuplexSpongeInterface, Encoding, Permutation};
use spongefish_circuit::{
    FieldVar, InvalidRelation, PermutationInstance, PermutationRelation, PermutationWitness,
    PermutationWitnessBuilder,
};

/// A toy bijection over bytes, enough to produce a trace.
#[derive(Clone, Default)]
struct Rotate;

impl Permutation<4> for Rotate {
    type U = u8;

    fn permute_mut(&self, state: &mut [u8; 4]) {
        *state = core::array::from_fn(|i| state[(i + 1) % 4].wrapping_add(i as u8 + 1));
    }
}

fn fixture() -> (PermutationInstance<u8, 4>, PermutationWitness<u8, 4>) {
    let tracer = PermutationWitnessBuilder::<Rotate, 4>::new(Rotate);
    let mut sponge = DuplexSponge::<_, 4, 2>::from(tracer.clone());
    let [digest] = sponge.absorb(&[1, 2]).absorb(&[3, 4]).squeeze_array();

    let relation = PermutationRelation::<u8, 4>::labeled("rotate/v1");
    let public = relation.allocate_vars_with(&[1, 2]);
    let secret = relation.allocate_vars::<2>();
    let mut sponge = DuplexSponge::<_, 4, 2>::from(relation.clone());
    let [out] = sponge.absorb(&public).absorb(&secret).squeeze_array();
    relation.set_var(out, digest);
    relation.add_equation(out * 0xFF + FieldVar::ZERO * 0, digest);

    (relation.compile().unwrap(), tracer.snapshot())
}

#[test]
fn instance_round_trips_through_bytes() {
    let (instance, _) = fixture();
    let bytes = instance.to_bytes();
    let parsed = PermutationInstance::<u8, 4>::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, instance);
    assert_eq!(parsed.label(), "rotate/v1");
    assert_eq!(parsed.to_bytes(), bytes);
    assert_eq!(instance.encode().as_ref(), bytes.as_slice());
    assert_eq!(&bytes[..4], b"SFRI");
}

#[test]
fn witness_round_trips_through_bytes() {
    let (instance, witness) = fixture();
    let bytes = witness.to_bytes();
    let parsed = PermutationWitness::<u8, 4>::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, witness);
    assert_eq!(&bytes[..4], b"SFRW");
    assert!(instance.is_witness_valid(&Rotate, &parsed));
}

#[test]
fn digest_is_stable_and_binding() {
    let (instance, _) = fixture();
    assert_eq!(instance.digest(), instance.digest());

    let relation = PermutationRelation::<u8, 4>::labeled("rotate/v2");
    let _ = relation.allocate_vars_with(&[1, 2]);
    let other = relation.compile().unwrap();
    assert_ne!(instance.digest(), other.digest());
}

#[test]
fn malformed_encodings_are_rejected() {
    let (instance, witness) = fixture();
    let bytes = instance.to_bytes();

    let reject = |bytes: &[u8]| -> InvalidRelation {
        PermutationInstance::<u8, 4>::from_bytes(bytes).expect_err("must be rejected")
    };

    let mut wrong_magic = bytes.clone();
    wrong_magic[0] = b'X';
    assert!(reject(&wrong_magic).message().contains("magic"));

    let mut wrong_version = bytes.clone();
    wrong_version[4] = 9;
    assert!(reject(&wrong_version).message().contains("version"));

    assert!(reject(&bytes[..bytes.len() - 1])
        .message()
        .contains("malformed"));

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(reject(&trailing).message().contains("trailing"));

    // The width is part of the type: the same bytes are not a width-8 instance.
    assert!(PermutationInstance::<u8, 8>::from_bytes(&bytes).is_err());

    // A witness is not an instance.
    assert!(reject(&witness.to_bytes()).message().contains("magic"));
    assert!(PermutationWitness::<u8, 4>::from_bytes(&bytes).is_err());
}

#[test]
fn parsing_runs_the_relation_checks() {
    let (instance, _) = fixture();
    let mut bytes = instance.to_bytes();
    // The first query's first input wire: after the header (magic, version,
    // width, unit length, label), vars_count, the public list, and n_queries.
    let header = 4 + 1 + 4 + 4 + 4 + "rotate/v1".len();
    let offset = header + 4 + 4 + 5 * instance.public_vars().len() + 4;
    bytes[offset..offset + 4].copy_from_slice(&1_000u32.to_le_bytes());
    let error = PermutationInstance::<u8, 4>::from_bytes(&bytes).expect_err("unallocated wire");
    assert!(error.message().contains("unallocated"), "{error}");
}

#[test]
fn wider_units_encode_with_their_width() {
    let relation = PermutationRelation::<u64, 2>::labeled("u64");
    let [a, b] = relation.allocate_vars_with(&[7, u64::MAX]);
    relation.add_permutation([a, b], [b, a]);
    let instance = relation.compile().unwrap();
    let bytes = instance.to_bytes();
    assert_eq!(
        PermutationInstance::<u64, 2>::from_bytes(&bytes).unwrap(),
        instance
    );
    // unit_len is 8 for u64.
    assert_eq!(&bytes[9..13], &8u32.to_le_bytes());
}
