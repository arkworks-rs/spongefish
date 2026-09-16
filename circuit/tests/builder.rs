#![cfg(feature = "p3-baby-bear")]

use p3_baby_bear::BabyBear;
use spongefish::{DuplexSponge, DuplexSpongeInterface, Permutation};
use spongefish_circuit::{
    baby_bear::BabyBearUnit, FieldVar, PermutationRelation, PermutationWitness,
    PermutationWitnessBuilder,
};

const fn bb(value: u32) -> BabyBearUnit {
    BabyBearUnit(BabyBear::new(value))
}

type Relation = PermutationRelation<BabyBearUnit, 16>;

/// A toy bijection, enough to exercise the bookkeeping.
#[derive(Clone, Default)]
struct Rotate;

impl Permutation<16> for Rotate {
    type U = BabyBearUnit;

    fn permute_mut(&self, state: &mut [BabyBearUnit; 16]) {
        *state = core::array::from_fn(|i| {
            let (x, y) = (state[i].0, state[(i + 1) % 16].0);
            BabyBearUnit(x * x * x + y)
        });
    }
}

/// Written once, run over wires and over values.
fn hash<S: DuplexSpongeInterface>(sponge: &mut S, public: &[S::U], secret: &[S::U]) -> [S::U; 4] {
    sponge.absorb(public).absorb(secret).squeeze_array()
}

const PUBLIC: [BabyBearUnit; 3] = [bb(1), bb(2), bb(3)];
const SECRET: [BabyBearUnit; 13] = [bb(7); 13];

/// The relation and the honest witness for `hash(PUBLIC, SECRET)`.
fn relation_and_witness() -> (
    Relation,
    PermutationWitness<BabyBearUnit, 16>,
    [BabyBearUnit; 4],
) {
    let tracer = PermutationWitnessBuilder::<Rotate, 16>::new(Rotate);
    let digest = hash(
        &mut DuplexSponge::<_, 16, 8>::from(tracer.clone()),
        &PUBLIC,
        &SECRET,
    );

    let relation = Relation::new();
    let public = relation.allocate_vars_with(&PUBLIC);
    let secret = relation.allocate_vars::<13>();
    let output = hash(
        &mut DuplexSponge::<_, 16, 8>::from(relation.clone()),
        &public,
        &secret,
    );
    relation.set_vars(output, digest);

    (relation, tracer.snapshot(), digest)
}

#[cfg(not(target_arch = "wasm32"))]
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
fn sponge_over_wires_records_one_query_per_permutation_call() {
    let (relation, _, _) = relation_and_witness();
    let instance = relation.compile().expect("valid relation");

    // Sixteen units absorbed at rate eight: two permutation calls.
    assert_eq!(instance.queries().len(), 2);
    assert_eq!(instance.vars_count(), relation.allocator().vars_count());
    // ZERO, the three public inputs, and the four outputs.
    assert_eq!(instance.public_vars().len(), 1 + 3 + 4);
    assert_eq!(instance.value(FieldVar::ZERO), Some(&bb(0)));
}

#[test]
fn honest_trace_is_a_valid_witness() {
    let (relation, witness, _) = relation_and_witness();
    let instance = relation.compile().unwrap();
    assert!(instance.is_witness_valid(&Rotate, &witness));
}

#[test]
fn wrong_public_output_is_rejected() {
    let (_, witness, digest) = relation_and_witness();
    // Same wiring, but the relation claims a different digest.
    let mut wrong = digest;
    wrong[0] = bb(0);

    let claimed = Relation::new();
    let public = claimed.allocate_vars_with(&PUBLIC);
    let secret = claimed.allocate_vars::<13>();
    let output = hash(
        &mut DuplexSponge::<_, 16, 8>::from(claimed.clone()),
        &public,
        &secret,
    );
    claimed.set_vars(output, wrong);

    assert!(!claimed
        .compile()
        .unwrap()
        .is_witness_valid(&Rotate, &witness));
}

#[test]
fn tampered_trace_is_rejected() {
    let (relation, _, _) = relation_and_witness();
    let instance = relation.compile().unwrap();

    let tracer = PermutationWitnessBuilder::<Rotate, 16>::new(Rotate);
    let honest = tracer.trace();
    // Rebuild the trace with a step that is not an evaluation of `Rotate`.
    let mut sponge = DuplexSponge::<_, 16, 8>::from(tracer.clone());
    let _ = hash(&mut sponge, &PUBLIC, &SECRET);
    let steps = tracer.trace();
    assert_eq!(honest.len(), 0);
    assert_eq!(steps.len(), 2);

    let forged = PermutationWitnessBuilder::<Rotate, 16>::new(Rotate);
    forged.add_permutation(&steps[0].input, &steps[0].output);
    forged.add_permutation(&steps[1].input, &[bb(9); 16]);
    assert!(!instance.is_witness_valid(&Rotate, &forged.snapshot()));

    let short = PermutationWitnessBuilder::<Rotate, 16>::new(Rotate);
    short.add_permutation(&steps[0].input, &steps[0].output);
    assert!(!instance.is_witness_valid(&Rotate, &short.snapshot()));
}

#[test]
fn linear_equations_are_built_with_operators() {
    let relation = Relation::new();
    let vars = relation.allocate_vars::<16>();
    let [a, b, c] = [vars[0], vars[1], vars[2]];
    relation.add_permutation(vars, vars);
    relation.add_equation(a * bb(1) + b + c, bb(0));
    relation.add_equation(c * bb(2) + a * bb(3), bb(7));

    let equations = relation.equations();
    assert_eq!(equations.len(), 2);
    assert_eq!(equations[0].terms.terms().len(), 3);
    assert_eq!(equations[0].terms.terms()[1].var, b);
    assert_eq!(equations[0].terms.terms()[1].weight, bb(1));
    assert_eq!(equations[0].image, bb(0));
    assert_eq!(equations[1].terms.terms()[0].weight, bb(2));
    assert_eq!(equations[1].image, bb(7));
    relation
        .compile()
        .expect("every wire is bound by the query");
}

#[test]
fn equations_are_checked_against_the_witness() {
    let (relation, witness, digest) = relation_and_witness();
    let [d0, d1, ..] = witness.trace()[1].output;
    assert_eq!(d0, digest[0]);

    // Which wires carry the digest: the first RATE outputs of the last query.
    let last = relation.queries()[1].clone();
    let (w0, w1) = (last.output[0], last.output[1]);

    relation.add_equation(w0 + w1 * bb(1), BabyBearUnit(d0.0 + d1.0));
    assert!(relation
        .compile()
        .unwrap()
        .is_witness_valid(&Rotate, &witness));

    relation.add_equation(w0 * bb(2), BabyBearUnit(d0.0 + d0.0 + BabyBear::new(1)));
    assert!(!relation
        .compile()
        .unwrap()
        .is_witness_valid(&Rotate, &witness));
}

#[test]
fn compile_rejects_weighted_unbound_wires_and_accepts_zero_weights() {
    let relation = Relation::new();
    let bound = relation.allocate_vars::<16>();
    let unbound = relation.allocate_var();
    relation.add_permutation(bound, bound);

    relation.add_equation(unbound * bb(0), bb(0));
    relation
        .compile()
        .expect("a zero weight constrains nothing");

    relation.add_equation(unbound * bb(1), bb(0));
    let error = relation
        .compile()
        .expect_err("unbound wire with nonzero weight");
    assert!(
        error
            .message()
            .contains("which no query or assignment binds"),
        "{error}"
    );
}

#[test]
fn compile_accepts_weighted_public_wires() {
    let relation = Relation::new();
    let public = relation.allocate_var_with(bb(5));
    relation.add_equation(public * bb(2), bb(10));
    let instance = relation.compile().unwrap();

    let empty = PermutationWitnessBuilder::<Rotate, 16>::new(Rotate).snapshot();
    assert!(instance.is_witness_valid(&Rotate, &empty));
}

#[test]
fn compile_rejects_unallocated_wires() {
    let relation = Relation::new();
    let vars = relation.allocate_vars::<16>();
    let foreign = FieldVar::try_from_index(1000).unwrap();
    let mut input = vars;
    input[3] = foreign;
    relation.add_permutation(input, vars);

    let error = relation.compile().expect_err("unallocated wire in a query");
    assert!(
        error.message().contains("unallocated variable 1000"),
        "{error}"
    );
}

#[test]
fn field_var_indices_are_bounded() {
    assert_eq!(
        FieldVar::try_from_index(FieldVar::MAX_COUNT - 1)
            .expect("last valid variable")
            .index(),
        FieldVar::MAX_COUNT - 1
    );
    assert!(FieldVar::try_from_index(FieldVar::MAX_COUNT).is_none());
}

#[test]
fn public_vars_are_returned_by_variable_index() {
    let relation = Relation::new();
    let [first, second] = relation.allocate_vars();

    relation.set_var(second, bb(2));
    relation.set_var(first, bb(1));

    assert_eq!(
        relation.public_vars(),
        vec![(FieldVar::ZERO, bb(0)), (first, bb(1)), (second, bb(2))]
    );
    assert_eq!(relation.allocator().value(second), Some(bb(2)));
    assert_eq!(relation.allocator().value(relation.allocate_var()), None);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn conflicting_assignments_panic() {
    let relation = Relation::new();
    let var = relation.allocate_var_with(bb(1));
    relation.set_var(var, bb(1));
    assert_panics_with("conflicting assignment", || relation.set_var(var, bb(2)));
    assert_panics_with("unallocated variable", || {
        relation.set_var(FieldVar::try_from_index(99).unwrap(), bb(2));
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn allocate_vars_vec_overflow_does_not_mutate_allocator() {
    let relation = Relation::new();
    let vars_count = relation.allocator().vars_count();

    assert_panics_with("variable count overflow", || {
        let _ = relation.allocate_vars_vec(usize::MAX);
    });

    assert_eq!(relation.allocator().vars_count(), vars_count);
}

#[test]
fn compiled_instances_are_immutable_after_relation_mutation() {
    let relation = Relation::new();
    let first = relation.allocate_vars::<16>();
    let _ = relation.allocate_permutation(&first);
    let instance = relation.compile().unwrap();

    let second = relation.allocate_vars::<16>();
    let _ = relation.allocate_permutation(&second);

    assert_eq!(instance.queries().len(), 1);
    assert_eq!(relation.queries().len(), 2);

    let tracer = PermutationWitnessBuilder::<Rotate, 16>::new(Rotate);
    let input = [bb(1); 16];
    let _ = tracer.allocate_permutation(&input);
    let witness = tracer.snapshot();
    let _ = tracer.allocate_permutation(&input);

    assert_eq!(witness.trace().len(), 1);
    assert_eq!(tracer.trace().len(), 2);
}

#[test]
fn relations_can_share_an_allocator() {
    let wide = Relation::new();
    let narrow = PermutationRelation::<BabyBearUnit, 4>::with_allocator(wide.allocator().clone());
    let shared = wide.allocate_var_with(bb(3));
    let input = [shared, FieldVar::ZERO, FieldVar::ZERO, FieldVar::ZERO];
    let _ = narrow.allocate_permutation(&input);

    assert!(wide.allocator().is_allocated(narrow.queries()[0].output[3]));
    narrow.compile().expect("the shared wire is allocated");
}
