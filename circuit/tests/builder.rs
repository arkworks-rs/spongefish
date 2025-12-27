use p3_baby_bear::BabyBear;
use spongefish::{DuplexSponge, DuplexSpongeInterface};
use spongefish_circuit::permutation::PermutationInstanceBuilder;

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
