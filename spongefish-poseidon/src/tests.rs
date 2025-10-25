use spongefish::duplex_sponge::Permutation;

#[allow(unused)]
fn test_vector<P: Permutation>(input: &[P::U], output: &[P::U])
where
    P::U: PartialEq + std::fmt::Debug,
{
    let mut hash = P::new();
    hash.as_mut().clone_from_slice(input);
    hash.permute();
    assert_eq!(hash.as_ref(), output);
}

#[cfg(feature = "bls12-381")]
#[test]
fn test_squeeze_bytes_from_algebraic_hash() {
    use spongefish::UnitToBytes;

    type F = ark_bls12_381::Fr;
    type H = crate::bls12_381::Poseidonx5_255_3;

    let domain_separator = spongefish::DomainSeparator::<H, F>::new("test").absorb(1, "in");
    let domain_separator = <spongefish::DomainSeparator<H, F> as spongefish::drivers::arkworks_algebra::ByteDomainSeparator>::challenge_bytes(
        domain_separator, 2048, "out",
    );
    let mut prover_state = domain_separator.to_prover_state();
    prover_state.add_units(&[F::from(0x42)]).unwrap();

    let mut prover_challenges = [0u8; 2048];
    prover_state
        .fill_challenge_bytes(&mut prover_challenges)
        .unwrap();

    let mut verifier_state = domain_separator.to_verifier_state(prover_state.narg_string());
    // write the unit to an throw-away array
    verifier_state.fill_next_units(&mut [F::from(0)]).unwrap();
    let verifier_challenges: [u8; 2048] = verifier_state.challenge_bytes().unwrap();

    assert_eq!(prover_challenges, verifier_challenges);
    let frequencies = (0u8..=255)
        .map(|i| prover_challenges.iter().filter(|&&x| x == i).count())
        .collect::<Vec<_>>();
    // each element should appear roughly 8 times on average. Checking we're not too far from that.
    assert!(
        frequencies.iter().all(|&x| x < 32 && x > 0),
        "This array should have random bytes but hasn't: {frequencies:?}"
    );
}

#[cfg(feature = "bls12-381")]
#[test]
fn test_poseidon_bls12_381() {
    use ark_ff::MontFp;
    use spongefish::{DomainSeparator, UnitTranscript};

    use crate::bls12_381::{PoseidonPermx5_255_3, PoseidonPermx5_255_5, Poseidonx5_255_3};

    type F = ark_bls12_381::Fr;

    let tv_x5_255_3_input: [F; 3] = [
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000001"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000002"),
    ];
    let tv_x5_255_3_output: [F; 3] = [
        MontFp!("0x28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a"),
        MontFp!("0x51f3e312c95343a896cfd8945ea82ba956c1118ce9b9859b6ea56637b4b1ddc4"),
        MontFp!("0x3b2b69139b235626a0bfb56c9527ae66a7bf486ad8c11c14d1da0c69bbe0f79a"),
    ];
    test_vector::<PoseidonPermx5_255_3>(&tv_x5_255_3_input, &tv_x5_255_3_output);

    let tv_x5_255_5_input: [F; 5] = [
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000001"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000002"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000003"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000004"),
    ];
    let tv_x5_255_5_output: [F; 5] = [
        MontFp!("0x2a918b9c9f9bd7bb509331c81e297b5707f6fc7393dcee1b13901a0b22202e18"),
        MontFp!("0x65ebf8671739eeb11fb217f2d5c5bf4a0c3f210e3f3cd3b08b5db75675d797f7"),
        MontFp!("0x2cc176fc26bc70737a696a9dfd1b636ce360ee76926d182390cdb7459cf585ce"),
        MontFp!("0x4dc4e29d283afd2a491fe6aef122b9a968e74eff05341f3cc23fda1781dcb566"),
        MontFp!("0x03ff622da276830b9451b88b85e6184fd6ae15c8ab3ee25a5667be8592cce3b1"),
    ];
    test_vector::<PoseidonPermx5_255_5>(&tv_x5_255_5_input, &tv_x5_255_5_output);

    // Check that poseidon can indeed be instantiated and doesn't do terribly stupid things like give 0 challenges.
    let domain_separator = DomainSeparator::<Poseidonx5_255_3, F>::new("test")
        .absorb(1, "in")
        .squeeze(10, "out");
    let mut prover_state = domain_separator.to_prover_state();
    prover_state.add_units(&[F::from(0x42)]).unwrap();

    let mut challenges = [F::from(0); 10];
    prover_state.fill_challenge_units(&mut challenges).unwrap();

    for challenge in challenges {
        assert_ne!(challenge, F::from(0));
    }
}

#[cfg(feature = "bn254")]
#[test]
fn test_poseidon_bn254() {
    use ark_ff::MontFp;

    use crate::bn254::{PoseidonPermx5_254_3, PoseidonPermx5_254_5};

    type F = ark_bn254::Fr;

    let tv_x5_254_3_input: [F; 3] = [
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000001"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000002"),
    ];
    let tv_x5_254_3_output: [F; 3] = [
        MontFp!("0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"),
        MontFp!("0x0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29"),
        MontFp!("0x0e7ae82e40091e63cbd4f16a6d16310b3729d4b6e138fcf54110e2867045a30c"),
    ];
    test_vector::<PoseidonPermx5_254_3>(&tv_x5_254_3_input, &tv_x5_254_3_output);

    let tv_x5_254_5_input: [F; 5] = [
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000001"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000002"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000003"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000004"),
    ];
    let tv_x5_254_5_output: [F; 5] = [
        MontFp!("0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465"),
        MontFp!("0x1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d"),
        MontFp!("0x24febb87fed7462e23f6665ff9a0111f4044c38ee1672c1ac6b0637d34f24907"),
        MontFp!("0x0eb08f6d809668a981c186beaf6110060707059576406b248e5d9cf6e78b3d3e"),
        MontFp!("0x07748bc6877c9b82c8b98666ee9d0626ec7f5be4205f79ee8528ef1c4a376fc7"),
    ];
    test_vector::<PoseidonPermx5_254_5>(&tv_x5_254_5_input, &tv_x5_254_5_output);
}

#[cfg(feature = "solinas")]
#[test]
fn test_poseidon_f64() {
    use ark_ff::MontFp;

    use crate::{f64, f64::PoseidonPermx3_64_24};
    type F = f64::Field64;

    let tv_x5_255_3_input: [F; 24] = [
        MontFp!("0x0000000000000000"),
        MontFp!("0x0000000000000001"),
        MontFp!("0x0000000000000002"),
        MontFp!("0x0000000000000003"),
        MontFp!("0x0000000000000004"),
        MontFp!("0x0000000000000005"),
        MontFp!("0x0000000000000006"),
        MontFp!("0x0000000000000007"),
        MontFp!("0x0000000000000008"),
        MontFp!("0x0000000000000009"),
        MontFp!("0x000000000000000a"),
        MontFp!("0x000000000000000b"),
        MontFp!("0x000000000000000c"),
        MontFp!("0x000000000000000d"),
        MontFp!("0x000000000000000e"),
        MontFp!("0x000000000000000f"),
        MontFp!("0x0000000000000010"),
        MontFp!("0x0000000000000011"),
        MontFp!("0x0000000000000012"),
        MontFp!("0x0000000000000013"),
        MontFp!("0x0000000000000014"),
        MontFp!("0x0000000000000015"),
        MontFp!("0x0000000000000016"),
        MontFp!("0x0000000000000017"),
    ];
    let tv_x5_255_3_output: [F; 24] = [
        MontFp!("0x213efd2211b3973a"),
        MontFp!("0x166d183ef79550cf"),
        MontFp!("0x59baa9e4812f63da"),
        MontFp!("0xd1b0c6d5cc76a062"),
        MontFp!("0x00730338e6873644"),
        MontFp!("0x817e3a361c89952c"),
        MontFp!("0x1fadd87f0f791faa"),
        MontFp!("0x7ec7fc90801acbcb"),
        MontFp!("0xb3a5a02a68f6ab59"),
        MontFp!("0x636b2871ca76d626"),
        MontFp!("0x9bf8320b55f7d177"),
        MontFp!("0x4728f3af5ff11f87"),
        MontFp!("0x0987fd5995343d35"),
        MontFp!("0x8e4865041b151fe4"),
        MontFp!("0x38323c44cf193b8a"),
        MontFp!("0xa74010a13b9a76a1"),
        MontFp!("0x429ebd654194eec2"),
        MontFp!("0xf116892e365bb752"),
        MontFp!("0xca1713b0b8861a67"),
        MontFp!("0xef097aa5eed74e30"),
        MontFp!("0x575030a5ef0cac85"),
        MontFp!("0xcbe04288de12090a"),
        MontFp!("0xd5f0afa1f6978fd3"),
        MontFp!("0x48b80826a5d068e6"),
    ];
    test_vector::<PoseidonPermx3_64_24>(&tv_x5_255_3_input, &tv_x5_255_3_output);
}
