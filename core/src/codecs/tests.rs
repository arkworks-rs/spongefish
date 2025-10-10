use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use group::GroupEncoding;

use crate::{
    codecs, keccak::Keccak, ByteDomainSeparator, DomainSeparator, DuplexSpongeInterface,
    UnitToBytes,
};

fn group_domain_separator<G, H>() -> DomainSeparator<H>
where
    G: group::Group,
    H: DuplexSpongeInterface,
    DomainSeparator<H>: super::zkcrypto_group::GroupDomainSeparator<G>
        + super::zkcrypto_group::FieldDomainSeparator<G::Scalar>,
{
    use codecs::zkcrypto_group::{FieldDomainSeparator, GroupDomainSeparator};

    DomainSeparator::new("github.com/mmaker/spongefish")
        .add_scalars(1, "com")
        .challenge_bytes(16, "chal")
        .add_points(1, "com")
        .challenge_bytes(16, "chal")
        .challenge_scalars(1, "chal")
}

fn ark_domain_separator<G, H>() -> DomainSeparator<H>
where
    G: ark_ec::CurveGroup,
    H: DuplexSpongeInterface,
    DomainSeparator<H>: super::arkworks_algebra::GroupDomainSeparator<G>
        + super::arkworks_algebra::FieldDomainSeparator<G::Scalar>,
{
    use codecs::arkworks_algebra::{FieldDomainSeparator, GroupDomainSeparator};

    DomainSeparator::new("github.com/mmaker/spongefish")
        .add_scalars(1, "com")
        .challenge_bytes(16, "chal")
        .add_points(1, "com")
        .challenge_bytes(16, "chal")
        .challenge_scalars(1, "chal")
}

#[test]
fn test_compatible_curve25519() {
    type ArkG = ark_curve25519::EdwardsProjective;
    type GroupG = curve25519_dalek::edwards::EdwardsPoint;
    compatible_groups::<ArkG, GroupG>();
}

#[test]
fn test_compatible_bls12_381() {
    type ArkG = ark_bls12_381::G1Projective;
    type GroupG = bls12_381::G1Projective;
    compatible_groups::<ArkG, GroupG>();
}

#[ignore = "arkworks adds trailing 0-byte"]
#[test]
fn test_compatible_pasta() {
    type ArkG = ark_vesta::Projective;
    type GroupG = pasta_curves::vesta::Point;
    compatible_groups::<ArkG, GroupG>();

    // type ArkG = ark_pallas::Projective;
    // type GroupG = pasta_curves::pallas::Point;
    // compatible_groups::<ArkG, GroupG>();
}

// Check that the transcripts generated using the Group trait can be compatible with transcripts generated using group.
fn compatible_groups<ArkG, GroupG>()
where
    ArkG: CurveGroup,
    GroupG: group::Group + GroupEncoding,
    GroupG::Repr: AsRef<[u8]>,
{
    use group::ff::PrimeField;

    let ark_scalar = ArkG::ScalarField::from(0x42);
    let group_scalar = GroupG::Scalar::from(0x42u64);
    // ***IMPORTANT***
    // Looks like group and arkworks use different generator points.
    let ark_generator = ArkG::generator();
    let group_generator = GroupG::generator();

    // **basic checks**
    // Check point encoding is the same in both libraries.
    let mut ark_generator_bytes = Vec::new();
    ark_generator
        .serialize_compressed(&mut ark_generator_bytes)
        .unwrap();
    let group_generator_bytes = <GroupG as GroupEncoding>::to_bytes(&group_generator);
    assert_eq!(&ark_generator_bytes, &group_generator_bytes.as_ref());
    // Check scalar encoding is the same in both libraries.
    let mut ark_scalar_bytes = Vec::new();
    ark_scalar
        .serialize_compressed(&mut ark_scalar_bytes)
        .unwrap();
    let group_scalar_bytes = group_scalar.to_repr();
    assert_eq!(&ark_scalar_bytes, group_scalar_bytes.as_ref());

    let ark_point = ark_generator * ark_scalar;
    let group_point = group_generator * group_scalar;

    let ark_domsep = ark_domain_separator::<ArkG, Keccak>();
    let group_domsep = group_domain_separator::<GroupG, Keccak>();
    let mut ark_chal = [0u8; 16];
    let mut group_chal = [0u8; 16];

    // Check that the domain separators are the same.
    let mut ark_prover = ark_domsep.to_prover_state();
    let mut group_prover = group_domsep.to_prover_state();
    assert_eq!(ark_domsep.as_bytes(), group_domsep.as_bytes());

    // Check that scalars absorption leads to the same transcript.
    codecs::arkworks_algebra::FieldToUnitSerialize::add_scalars(&mut ark_prover, &[ark_scalar])
        .unwrap();
    ark_prover.fill_challenge_bytes(&mut ark_chal).unwrap();
    codecs::zkcrypto_group::FieldToUnitSerialize::add_scalars(&mut group_prover, &[group_scalar])
        .unwrap();
    group_prover.fill_challenge_bytes(&mut group_chal).unwrap();
    assert_eq!(ark_chal, group_chal);

    // Check that points absorption leads to the same transcript.
    codecs::arkworks_algebra::GroupToUnitSerialize::add_points(&mut ark_prover, &[ark_point])
        .unwrap();
    ark_prover.fill_challenge_bytes(&mut ark_chal).unwrap();
    codecs::zkcrypto_group::GroupToUnitSerialize::add_points(&mut group_prover, &[group_point])
        .unwrap();
    group_prover.fill_challenge_bytes(&mut group_chal).unwrap();
    assert_eq!(ark_chal, group_chal);

    // Check that scalars challenges are interpreted in the same way from bytes.
    let [ark_chal_scalar]: [ArkG::ScalarField; 1] =
        codecs::arkworks_algebra::UnitToField::challenge_scalars(&mut ark_prover).unwrap();
    let [group_chal_scalar]: [GroupG::Scalar; 1] =
        codecs::zkcrypto_group::UnitToField::challenge_scalars(&mut group_prover).unwrap();
    let mut ark_scalar_bytes = Vec::new();
    ark_chal_scalar
        .serialize_compressed(&mut ark_scalar_bytes)
        .unwrap();
    let group_scalar_bytes = group_chal_scalar.to_repr();
    assert_eq!(&ark_scalar_bytes, group_scalar_bytes.as_ref());
}
