use p3_baby_bear::BabyBear;
use spongefish::{DuplexSponge, DuplexSpongeInterface, Permutation};
use spongefish_circuit::{
    allocator::FieldVar,
    permutation::{LinearEquation, PermutationInstanceBuilder, PermutationWitnessBuilder},
};

type TestInstanceBuilder = PermutationInstanceBuilder<BabyBear, 16>;

#[derive(Clone, Default)]
struct DummyPermutation;

impl Permutation<16> for DummyPermutation {
    type U = BabyBear;

    fn permute(&self, state: &[Self::U; 16]) -> [Self::U; 16] {
        *state
    }
}

fn instance_builder() -> TestInstanceBuilder {
    PermutationInstanceBuilder::new()
}

fn assert_panics_with(expected: &str, f: impl FnOnce()) {
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .expect_err("expected closure to panic");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("<non-string panic>");

    assert!(
        message.contains(expected),
        "panic message {message:?} did not contain {expected:?}",
    );
}

#[test]
pub fn test_xof() {
    // Create a new dummy permutation.
    // The permutation contains internally a "FieldVar" allocator, which is simply a `usize`
    // representing a field variable.
    let inst_builder = instance_builder();

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
        .set_public_vars(&xof_output, [BabyBear::new(42); 4]);

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
    let inst_builder = instance_builder();
    let vars = inst_builder.allocator().allocate_vars::<16>();
    let [a, b, c] = [vars[0], vars[1], vars[2]];
    inst_builder.add_permutation(vars, vars);
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
pub fn field_var_indices_are_bounded() {
    assert_eq!(
        FieldVar::try_from_index(FieldVar::MAX_COUNT - 1)
            .expect("last valid variable")
            .index(),
        FieldVar::MAX_COUNT - 1
    );
    assert!(FieldVar::try_from_index(FieldVar::MAX_COUNT).is_none());
}

#[test]
pub fn public_vars_are_returned_by_variable_index() {
    let inst_builder = instance_builder();
    let [first, second] = inst_builder.allocator().allocate_vars();

    inst_builder
        .allocator()
        .set_public_var(second, BabyBear::new(2));
    inst_builder
        .allocator()
        .set_public_var(first, BabyBear::new(1));

    assert_eq!(
        inst_builder.allocator().public_vars(),
        vec![
            (FieldVar::ZERO, BabyBear::new(0)),
            (first, BabyBear::new(1)),
            (second, BabyBear::new(2)),
        ]
    );
}

#[test]
pub fn linear_equation_terms_must_be_bound_unless_zero() {
    let inst_builder = instance_builder();
    let bound_vars = inst_builder.allocator().allocate_vars::<16>();
    let [unbound_var] = inst_builder.allocator().allocate_vars();
    inst_builder.add_permutation(bound_vars, bound_vars);

    assert_panics_with(
        "nonzero linear terms must reference a permutation input or output variable",
        || {
            inst_builder.add_equation(LinearEquation::new(
                [(BabyBear::new(1), unbound_var)],
                BabyBear::new(0),
            ));
        },
    );

    inst_builder.add_equation(LinearEquation::new(
        [(BabyBear::new(0), unbound_var)],
        BabyBear::new(0),
    ));

    assert_eq!(inst_builder.linear_constraints().as_ref().len(), 1);
}

#[test]
pub fn allocate_vars_vec_overflow_does_not_mutate_allocator() {
    let inst_builder = instance_builder();
    let allocator = inst_builder.allocator();
    let vars_count = allocator.vars_count();

    assert_panics_with("variable count overflow", || {
        let _ = allocator.allocate_vars_vec(usize::MAX);
    });

    assert_eq!(allocator.vars_count(), vars_count);
}

#[test]
pub fn snapshots_are_immutable_after_builder_mutation() {
    let inst_builder = instance_builder();
    let first_vars = inst_builder.allocator().allocate_vars::<16>();
    let _ = inst_builder.allocate_permutation(&first_vars);
    let instance_snapshot = inst_builder.snapshot();

    let second_vars = inst_builder.allocator().allocate_vars::<16>();
    let _ = inst_builder.allocate_permutation(&second_vars);

    assert_eq!(instance_snapshot.constraints().as_ref().len(), 1);
    assert_eq!(inst_builder.constraints().as_ref().len(), 2);

    let witness = PermutationWitnessBuilder::<DummyPermutation, 16>::new(DummyPermutation);
    let input = [BabyBear::new(1); 16];
    let _ = witness.allocate_permutation(&input);
    let witness_snapshot = witness.snapshot();
    let _ = witness.allocate_permutation(&input);

    assert_eq!(witness_snapshot.trace().as_ref().len(), 1);
    assert_eq!(witness.trace().as_ref().len(), 2);
}
