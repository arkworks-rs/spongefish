use spongefish::{instantiations::KeccakF1600, DuplexSponge, DuplexSpongeInterface};
use spongefish_circuit::{
    PermutationInstance, PermutationRelation, PermutationWitnessBuilder, Ring,
};

/// An extendable-output function, written once against the sponge.
fn xof<S: DuplexSpongeInterface>(sponge: &mut S, input: &[S::U], len: usize) -> Box<[S::U]> {
    sponge.absorb(input).squeeze_boxed(len)
}

/// Duplex authenticated encryption, illustrative: the keystream is the
/// squeezed rate, the plaintext is absorbed back, and the tag is squeezed
/// from the state that saw it.
fn encrypt<S: DuplexSpongeInterface<U = u8>>(
    sponge: &mut S,
    key: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let keystream = xof(sponge, key, plaintext.len());
    let ciphertext = plaintext
        .iter()
        .zip(&keystream)
        .map(|(p, k)| p ^ k)
        .collect();
    let tag = sponge.absorb(plaintext).squeeze_array();
    (ciphertext, tag)
}

/// Over the relation the sponge sees the key and the plaintext, the tag is
/// public, and the ciphertext is the public image of one XOR equation per
/// byte.
fn encryption_relation(ciphertext: &[u8], tag: &[u8; 16]) -> PermutationInstance<u8, 200> {
    let relation = PermutationRelation::<u8, 200>::labeled("keccak-f[1600]");
    let key = relation.allocate_vars::<3>();
    let plaintext = relation.allocate_vars_vec(ciphertext.len());
    let mut sponge = DuplexSponge::<_, 200, 136>::from(relation.clone());
    let keystream = xof(&mut sponge, &key, plaintext.len());
    for ((k, p), c) in keystream.iter().zip(&plaintext).zip(ciphertext) {
        relation.add_equation(*k * 0xFF + *p, *c);
    }
    let tag_wires: [_; 16] = sponge.absorb(&plaintext).squeeze_array();
    relation.set_vars(tag_wires, tag);
    relation.compile().unwrap()
}

#[test]
fn integer_units_form_the_boolean_ring() {
    assert_eq!(<u8 as Ring>::ONE, 0xFF);
    assert_eq!(Ring::add(0b1100u8, 0b1010), 0b0110);
    assert_eq!(Ring::mul(0b1100u8, 0b1010), 0b1000);
}

#[test]
fn duplex_encryption_is_an_xor_relation() {
    let tracer = PermutationWitnessBuilder::<KeccakF1600, 200>::new(KeccakF1600);
    let (ciphertext, tag) = encrypt(
        &mut DuplexSponge::<_, 200, 136>::from(tracer.clone()),
        b"key",
        b"attack at dawn",
    );

    let instance = encryption_relation(&ciphertext, &tag);
    assert_eq!(instance.queries().len(), 2);
    assert_eq!(instance.equations().len(), 14);
    assert!(instance.is_witness_valid(&KeccakF1600, &tracer.snapshot()));

    // A relation claiming another ciphertext byte, or another tag, is not
    // satisfied.
    let mut wrong = ciphertext.clone();
    wrong[0] ^= 1;
    assert!(!encryption_relation(&wrong, &tag).is_witness_valid(&KeccakF1600, &tracer.snapshot()));
    let mut wrong_tag = tag;
    wrong_tag[0] ^= 1;
    assert!(!encryption_relation(&ciphertext, &wrong_tag)
        .is_witness_valid(&KeccakF1600, &tracer.snapshot()));
}

/// A weight selects bits: the low nibble of a wire must be zero.
#[test]
fn weights_are_masks() {
    let relation = PermutationRelation::<u8, 4>::new();
    let wire = relation.allocate_var_with(0xA0);
    relation.add_equation(wire * 0x0F, 0);
    let instance = relation.compile().unwrap();
    let empty = PermutationWitnessBuilder::<Rotate, 4>::new(Rotate).snapshot();
    assert!(instance.is_witness_valid(&Rotate, &empty));

    let relation = PermutationRelation::<u8, 4>::new();
    let wire = relation.allocate_var_with(0xA1);
    relation.add_equation(wire * 0x0F, 0);
    assert!(!relation
        .compile()
        .unwrap()
        .is_witness_valid(&Rotate, &empty));
}

#[derive(Clone, Default)]
struct Rotate;

impl spongefish::Permutation<4> for Rotate {
    type U = u8;

    fn permute_mut(&self, state: &mut [u8; 4]) {
        state.rotate_left(1);
    }
}
