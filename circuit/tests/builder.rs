use p3_baby_bear::BabyBear;
use spongefish::{DuplexSponge, DuplexSpongeInterface, Permutation};
use spongefish_circuit::permutation::{
    LinearEquation, PermutationInstanceBuilder, PermutationWitnessBuilder,
};

#[derive(Clone, Default)]
struct DummyPermutation;

impl Permutation<16> for DummyPermutation {
    type U = BabyBear;

    fn permute(&self, state: &[Self::U; 16]) -> [Self::U; 16] {
        *state
    }
}

#[test]
pub fn test_xof() {
    // Create a new dummy permutation.
    // The permutation contains internally a "FieldVar" allocator, which is simply a `usize`
    // representing a field variable.
    let inst_builder = PermutationInstanceBuilder::<BabyBear, 16>::new();

    // You can access the allocator with .allocator()..
    // .. and allocate new variables (in this case 13) that are private ..
    let secret = inst_builder.allocator().allocate_vars::<13>();
    // .. or public variables for which the value is known.
    let public = inst_builder.allocator().allocate_public(&[
        BabyBear::new(1),
        BabyBear::new(2),
        BabyBear::new(3),
    ]);

    // Build the duplex sponge construction over this "permutation" with parameters:
    // WIDTH = 16
    // RATE = 8 (so the sponge capacity is 8)
    // `inst_builder` is reference-counted.
    let mut sponge = DuplexSponge::<_, 16, 8>::from(inst_builder.clone());

    // Use the sponge as an xof and get 4 field elements as outputs.
    // This is common when you want to hash a secret and do domain separation.
    // This could also have been a separate function working over a generic DuplexSponge<P: Permutation>
    // running native code.
    let xof_output = sponge.absorb(&public).absorb(&secret).squeeze_boxed(4);

    // Let's assume the output is public (that's the case in Fiat-Shamir or in encryption)
    inst_builder
        .allocator()
        .set_public_vars(&xof_output, [BabyBear::new(42); 3]);

    // Since rate = 8 and |public + secret| = 16
    // we have invoked the permutation function twice.
    assert_eq!(xof_output.len(), 4);
    assert_eq!(inst_builder.constraints().as_ref().len(), 2);

    // the instance is a set of:
    println!(
        "input/otutput vars: {:?}",
        inst_builder.constraints().as_ref()
    );
    println!("public vars: {:?}", inst_builder.allocator().public_vars());
}

#[test]
pub fn test_linear_equations() {
    let inst_builder = PermutationInstanceBuilder::<BabyBear, 16>::new();
    let [a, b, c] = inst_builder.allocator().allocate_vars();
    inst_builder.add_equation(LinearEquation::new(
        [
            (BabyBear::new(1), a),
            (BabyBear::new(1), b),
            (BabyBear::new(1), c),
        ],
        BabyBear::new(0),
    ));
    inst_builder.add_equation(LinearEquation::new(
        [(BabyBear::new(2), c), (BabyBear::new(3), a)],
        BabyBear::new(7),
    ));

    let equations = inst_builder.linear_constraints();
    assert_eq!(equations.as_ref().len(), 2);
    assert_eq!(
        equations.as_ref()[0].linear_combination,
        vec![
            (BabyBear::new(1), a),
            (BabyBear::new(1), b),
            (BabyBear::new(1), c),
        ]
    );
    assert_eq!(equations.as_ref()[0].image, BabyBear::new(0));
    assert_eq!(equations.as_ref()[1].image, BabyBear::new(7));
}

#[test]
pub fn test_witness_linear_equations() {
    let witness = PermutationWitnessBuilder::<DummyPermutation, 16>::new(DummyPermutation);
    witness.add_equation(LinearEquation::new(
        [
            (BabyBear::new(2), BabyBear::new(3)),
            (BabyBear::new(4), BabyBear::new(5)),
            (BabyBear::new(6), BabyBear::new(8)),
        ],
        BabyBear::new(9),
    ));

    let equations = witness.linear_constraints();
    assert_eq!(equations.as_ref().len(), 1);
    assert_eq!(equations.as_ref()[0].linear_combination.len(), 3);
    assert_eq!(
        equations.as_ref()[0].linear_combination[2],
        (BabyBear::new(6), BabyBear::new(8))
    );
    assert_eq!(equations.as_ref()[0].image, BabyBear::new(9));
}

#[test]
pub fn test_instance_builder_reuses_identical_permutations() {
    let inst_builder = PermutationInstanceBuilder::<BabyBear, 16>::new();
    let input = inst_builder.allocator().allocate_vars::<16>();

    let first_output = inst_builder.allocate_permutation(&input);
    let second_output = inst_builder.allocate_permutation(&input);

    assert_eq!(first_output, second_output);
    assert_eq!(inst_builder.constraints().as_ref().len(), 1);
}

#[test]
pub fn test_witness_builder_reuses_identical_permutations() {
    let witness =
        PermutationWitnessBuilder::<SpongePoseidon2_16, 16>::new(SpongePoseidon2_16::default());
    let input = [BabyBear::new(7); 16];

    let first_output = witness.allocate_permutation(&input);
    let second_output = witness.allocate_permutation(&input);

    assert_eq!(first_output, second_output);
    assert_eq!(witness.trace().as_ref().len(), 1);
}

#[test]
pub fn test_allocator_reuses_public_constants_with_dedup_api() {
    let inst_builder = PermutationInstanceBuilder::<BabyBear, 16>::new();
    let vars = inst_builder.allocator().allocate_public_dedup(&[
        BabyBear::new(7),
        BabyBear::new(7),
        BabyBear::new(9),
        BabyBear::new(7),
    ]);

    assert_eq!(vars[0], vars[1]);
    assert_eq!(vars[0], vars[3]);
    assert_ne!(vars[0], vars[2]);
    assert_eq!(inst_builder.allocator().public_vars().len(), 3);
}
