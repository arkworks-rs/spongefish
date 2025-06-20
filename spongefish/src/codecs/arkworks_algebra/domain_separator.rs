use ark_ec::CurveGroup;
use ark_ff::{Field, Fp, FpConfig, PrimeField};

use super::{FieldPattern, GroupPattern};
use crate::{
    codecs::{
        bytes::{self, Pattern as _},
        bytes_modp, bytes_uniform_modp,
        unit::{self, Pattern as _},
    },
    pattern::{self, Label, Length, Pattern as _, PatternState},
};

impl<F> FieldPattern<F> for PatternState
where
    F: Field,
{
    fn message_scalars(&mut self, label: Label, count: usize) {
        self.begin_message::<F>(label, Length::Fixed(count));
        self.message_bytes(
            "base-field-coefficients-little-endian",
            count
                * F::extension_degree() as usize
                * bytes_modp(F::BasePrimeField::MODULUS_BIT_SIZE),
        );
        self.end_message::<F>(label, Length::Fixed(count));
    }

    fn challenge_scalars(&mut self, label: Label, count: usize) {
        self.begin_challenge::<F>(label, Length::Fixed(count));
        self.challenge_bytes(
            "base-field-coefficients-little-endian",
            count
                * F::extension_degree() as usize
                * bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE),
        );
        self.end_challenge::<F>(label, Length::Fixed(count));
    }
}

impl<F, C, const N: usize> FieldPattern<F> for PatternState<Fp<C, N>>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    C: FpConfig<N>,
{
    fn message_scalars(&mut self, label: Label, count: usize) {
        self.begin_message::<F>(label, Length::Fixed(count));
        self.message_units(
            "base-field-coefficients",
            count * F::extension_degree() as usize,
        );
        self.end_message::<F>(label, Length::Fixed(count));
    }

    fn challenge_scalars(&mut self, label: Label, count: usize) {
        self.begin_challenge::<F>(label, Length::Fixed(count));
        self.challenge_units(
            "base-field-coefficients",
            count * F::extension_degree() as usize,
        );
        self.end_challenge::<F>(label, Length::Fixed(count));
    }
}

/// Implementation where `Unit = Fp<C, N>`
impl<C, const N: usize> bytes::Pattern for PatternState<Fp<C, N>>
where
    C: FpConfig<N>,
{
    /// Add `count` bytes to the transcript, encoding each of them as an element of the field `Fp`.
    fn public_bytes(&mut self, label: Label, size: usize) {
        self.begin_public::<u8>(label, Length::Fixed(size));
        self.public_units("units", size);
        self.end_public::<u8>(label, Length::Fixed(size))
    }

    /// Add `count` bytes to the transcript, encoding each of them as an element of the field `Fp`.
    fn message_bytes(&mut self, label: Label, size: usize) {
        self.begin_message::<u8>(label, Length::Fixed(size));
        self.message_units("units", size);
        self.end_message::<u8>(label, Length::Fixed(size))
    }

    fn challenge_bytes(&mut self, label: Label, size: usize) {
        self.begin_challenge::<u8>(label, Length::Fixed(size));
        let n = crate::codecs::random_bits_in_random_modp(Fp::<C, N>::MODULUS) / 8;
        self.challenge_units("units", size.div_ceil(n));
        self.end_challenge::<u8>(label, Length::Fixed(size))
    }
}

impl<G> GroupPattern<G> for PatternState<u8>
where
    G: CurveGroup,
{
    fn message_points(&mut self, label: Label, count: usize) {
        self.begin_message::<G>(label, Length::Fixed(count));
        self.message_bytes("serialized-group", count * G::default().compressed_size());
        self.end_message::<G>(label, Length::Fixed(count));
    }
}

impl<G, C, const N: usize> GroupPattern<G> for PatternState<Fp<C, N>>
where
    G: CurveGroup<BaseField = Fp<C, N>>,
    C: FpConfig<N>,
{
    fn message_points(&mut self, label: Label, count: usize) {
        self.begin_message::<G>(label, Length::Fixed(count));
        self.message_units("coordinates", count * 2);
        self.end_message::<G>(label, Length::Fixed(count));
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fq2, Fr};
    use ark_curve25519::EdwardsProjective as Curve;
    use ark_ff::{
        AdditiveGroup, Fp2, Fp2Config, Fp4, Fp4Config, Fp64, MontBackend, MontConfig, MontFp,
        PrimeField,
    };

    use super::*;
    use crate::{
        pattern::{InteractionPattern, Pattern},
        DefaultHash,
    };

    /// Configuration for the BabyBear field (modulus = 2^31 - 2^27 + 1, generator = 21).
    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearConfig;

    /// Base field type using the BabyBear configuration.
    pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;

    /// Quadratic extension field over BabyBear.
    pub type BabyBear2 = Fp2<F2Config64>;

    /// Configuration for the quadratic extension BabyBear2.
    pub struct F2Config64;

    impl Fp2Config for F2Config64 {
        type Fp = BabyBear;

        // Mocked value: not used in tests
        const NONRESIDUE: Self::Fp = BabyBear::ZERO;

        // Mocked value: not used in tests
        const FROBENIUS_COEFF_FP2_C1: &'static [Self::Fp] = &[BabyBear::ZERO];
    }

    /// Quartic extension field over BabyBear using nested Fp2 extensions.
    pub type BabyBear4 = Fp4<F4Config64>;

    /// Configuration for the quartic extension BabyBear4.
    pub struct F4Config64;

    impl Fp4Config for F4Config64 {
        type Fp2Config = F2Config64;

        // Mocked value: not used in tests
        const NONRESIDUE: Fp2<Self::Fp2Config> = Fp2::<Self::Fp2Config>::ZERO;

        // Mocked value: not used in tests
        const FROBENIUS_COEFF_FP4_C1: &'static [<Self::Fp2Config as Fp2Config>::Fp] = &[];
    }

    #[test]
    fn test_domain_separator() {
        // OPTION 1 (fails)
        // let domain_separator = DomainSeparator::new("github.com/mmaker/spongefish")
        //     .absorb_points(1, "g")
        //     .absorb_points(1, "pk")
        //     .ratchet()
        //     .absorb_points(1, "com")
        //     .squeeze_scalars(1, "chal")
        //     .absorb_scalars(1, "resp");

        // // OPTION 2
        fn add_schnorr_domain_separator<P, G: ark_ec::CurveGroup>(pattern: &mut P)
        where
            P: pattern::Pattern + unit::Pattern + FieldPattern<G::BaseField> + GroupPattern<G>,
        {
            pattern.begin_protocol::<()>("github.com/mmaker/spongefish");
            pattern.message_points("g", 1);
            pattern.message_points("pk", 1);
            pattern.ratchet();
            pattern.message_points("com", 1);
            pattern.challenge_scalars("chal", 1);
            pattern.message_scalars("resp", 1);
            pattern.end_protocol::<()>("github.com/mmaker/spongefish");
        }
        let mut pattern = PatternState::<u8>::new();
        add_schnorr_domain_separator::<_, ark_curve25519::EdwardsProjective>(&mut pattern);
        let pattern = pattern.finalize();

        // OPTION 3 (extra type, trait extensions should be on DomainSeparator or AlgebraicDomainSeparator?)
        // let domain_separator =
        //     ArkGroupDomainSeparator::<ark_curve25519::EdwardsProjective>::new("github.com/mmaker/spongefish")
        //         .add_points(1, "g")
        //         .add_points(1, "pk")
        //         .ratchet()
        //         .add_points(1, "com")
        //         .challenge_scalars(1, "chal")
        //         .add_scalars(1, "resp");

        assert_eq!(
            format!("{pattern}"),
            r#"Spongefish Transcript (28 interactions)
00 Begin Protocol github.com/mmaker/spongefish None ()
01   Begin Message g Fixed(1) ark_ec::models::twisted_edwards::group::Projective<ark_curve25519::curves::Curve25519Config>
02     Begin Message serialized-group Fixed(32) u8
03       Atomic Message units Fixed(32) u8
04     End Message serialized-group Fixed(32) u8
05   End Message g Fixed(1) ark_ec::models::twisted_edwards::group::Projective<ark_curve25519::curves::Curve25519Config>
06   Begin Message pk Fixed(1) ark_ec::models::twisted_edwards::group::Projective<ark_curve25519::curves::Curve25519Config>
07     Begin Message serialized-group Fixed(32) u8
08       Atomic Message units Fixed(32) u8
09     End Message serialized-group Fixed(32) u8
10   End Message pk Fixed(1) ark_ec::models::twisted_edwards::group::Projective<ark_curve25519::curves::Curve25519Config>
11   Atomic Protocol ratchet None ()
12   Begin Message com Fixed(1) ark_ec::models::twisted_edwards::group::Projective<ark_curve25519::curves::Curve25519Config>
13     Begin Message serialized-group Fixed(32) u8
14       Atomic Message units Fixed(32) u8
15     End Message serialized-group Fixed(32) u8
16   End Message com Fixed(1) ark_ec::models::twisted_edwards::group::Projective<ark_curve25519::curves::Curve25519Config>
17   Begin Challenge chal Fixed(1) ark_ff::fields::models::fp::Fp<ark_ff::fields::models::fp::montgomery_backend::MontBackend<ark_curve25519::fields::fq::FqConfig, 4>, 4>
18     Begin Challenge base-field-coefficients-little-endian Fixed(47) u8
19       Atomic Challenge units Fixed(47) u8
20     End Challenge base-field-coefficients-little-endian Fixed(47) u8
21   End Challenge chal Fixed(1) ark_ff::fields::models::fp::Fp<ark_ff::fields::models::fp::montgomery_backend::MontBackend<ark_curve25519::fields::fq::FqConfig, 4>, 4>
22   Begin Message resp Fixed(1) ark_ff::fields::models::fp::Fp<ark_ff::fields::models::fp::montgomery_backend::MontBackend<ark_curve25519::fields::fq::FqConfig, 4>, 4>
23     Begin Message base-field-coefficients-little-endian Fixed(32) u8
24       Atomic Message units Fixed(32) u8
25     End Message base-field-coefficients-little-endian Fixed(32) u8
26   End Message resp Fixed(1) ark_ff::fields::models::fp::Fp<ark_ff::fields::models::fp::montgomery_backend::MontBackend<ark_curve25519::fields::fq::FqConfig, 4>, 4>
27 End Protocol github.com/mmaker/spongefish None ()
"#
        );
    }

    // #[test]
    // fn test_scalar_vs_byte_equivalence_field_modp() {
    //     type F = Fr;

    //     let label = "same-scalar";
    //     // Compute number of bytes needed to represent one scalar
    //     let scalar_bytes = bytes_modp(F::MODULUS_BIT_SIZE);

    //     // Add one scalar to the transcript using the scalar API
    //     let scalar_sep = <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(
    //         DomainSeparator::<DefaultHash>::new("label"),
    //         1,
    //         label,
    //     );

    //     // Add the same number of bytes directly
    //     let byte_sep = DomainSeparator::<DefaultHash>::new("label").add_bytes(scalar_bytes, label);

    //     // Ensure the encodings are equal
    //     assert_eq!(scalar_sep.as_bytes(), byte_sep.as_bytes());
    // }

    // #[test]
    // fn test_challenge_scalars_vs_bytes_equivalence() {
    //     type F = Fr;

    //     let label = "challenge";
    //     // Compute the number of bytes needed for one uniform scalar
    //     let uniform_bytes = bytes_uniform_modp(F::MODULUS_BIT_SIZE);

    //     // Request 2 scalar challenges
    //     let sep_scalar = <DomainSeparator as FieldDomainSeparator<F>>::challenge_scalars(
    //         DomainSeparator::<DefaultHash>::new("L"),
    //         2,
    //         label,
    //     );

    //     // Request 2 * bytes directly
    //     let sep_bytes =
    //         DomainSeparator::<DefaultHash>::new("L").challenge_bytes(2 * uniform_bytes, label);

    //     // Ensure the encodings match
    //     assert_eq!(sep_scalar.as_bytes(), sep_bytes.as_bytes());
    // }

    // #[test]
    // fn test_domain_separator_fq2_bytes_are_expected() {
    //     type F = Fq2;

    //     // Construct the separator with one Fq2 absorbed and one Fq2 squeezed
    //     let sep = <DomainSeparator as FieldDomainSeparator<F>>::challenge_scalars(
    //         <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(
    //             DomainSeparator::<DefaultHash>::new("ark-fq2"),
    //             1,
    //             "a",
    //         ),
    //         1,
    //         "b",
    //     );

    //     // Explanation of the expected encoding:
    //     // "ark-fq2"             → domain label
    //     // "\0A96a"              → absorb 96 bytes (Fq2 = 2 × 48)
    //     // "\0S126b"             → squeeze 126 bytes (Fq2 = 2 × 63 uniform bytes)
    //     let expected_bytes = b"ark-fq2\0A96a\0S126b";
    //     assert_eq!(sep.as_bytes(), expected_bytes);
    // }

    // #[test]
    // fn test_group_point_encoding_vs_bytes_direct() {
    //     type G = Curve;

    //     // Add 2 group elements to the transcript (compressed size = 32 each)
    //     let point_sep = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
    //         DomainSeparator::<DefaultHash>::new("G"),
    //         2,
    //         "X",
    //     );

    //     // Add 64 raw bytes directly instead
    //     let byte_sep = DomainSeparator::<DefaultHash>::new("G").add_bytes(64, "X");

    //     // Ensure they are equivalent
    //     assert_eq!(point_sep.as_bytes(), byte_sep.as_bytes());
    // }

    // #[test]
    // fn test_domain_separator_determinism() {
    //     type G = Curve;
    //     type F = Fr;

    //     // First sequence: add group point, absorb scalar, squeeze scalar
    //     let add_pts = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
    //         DomainSeparator::<DefaultHash>::new("proof"),
    //         1,
    //         "pk",
    //     );
    //     let add_scalars =
    //         <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(add_pts, 1, "x");
    //     let d1 =
    //         <DomainSeparator as FieldDomainSeparator<F>>::challenge_scalars(add_scalars, 1, "y");

    //     // Repeat the same sequence again
    //     let add_pts_2 = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
    //         DomainSeparator::<DefaultHash>::new("proof"),
    //         1,
    //         "pk",
    //     );
    //     let add_scalars_2 =
    //         <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(add_pts_2, 1, "x");
    //     let d2 =
    //         <DomainSeparator as FieldDomainSeparator<F>>::challenge_scalars(add_scalars_2, 1, "y");

    //     // Resulting byte encodings must be the same
    //     assert_eq!(d1.as_bytes(), d2.as_bytes());
    // }

    // #[test]
    // fn test_group_and_field_mixed_usage_structure() {
    //     type G = Curve;
    //     type F = Fr;

    //     // Add one group element (compressed 32 bytes)
    //     let step1 = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
    //         DomainSeparator::<DefaultHash>::new("joint"),
    //         1,
    //         "pk",
    //     );
    //     // Ratchet separator state
    //     let step2 = step1.ratchet();
    //     // Add two scalars → 2 × 32 bytes = 64
    //     let step3 = <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(step2, 2, "resp");
    //     // Squeeze one scalar → 32 bytes uniform modp = 47
    //     let sep = <DomainSeparator as FieldDomainSeparator<F>>::challenge_scalars(step3, 1, "c");

    //     // "joint"          → domain label
    //     // "\0A32pk"        → absorb 32 bytes (1 group point)
    //     // "\0R"            → ratchet
    //     // "\0A64resp"      → absorb 64 bytes (2 Fr)
    //     // "\0S47c"         → squeeze 47 bytes (1 Fr uniform)
    //     assert_eq!(sep.as_bytes(), b"joint\0A32pk\0R\0A64resp\0S47c");
    // }

    // #[test]
    // fn test_field_domain_separator_for_custom_fp() {
    //     #[derive(MontConfig)]
    //     #[modulus = "18446744069414584321"]
    //     #[generator = "7"]
    //     pub struct FConfig64;
    //     pub type Field64 = Fp64<MontBackend<FConfig64, 1>>;

    //     pub type Field64_2 = Fp2<F2Config64>;
    //     pub struct F2Config64;
    //     impl Fp2Config for F2Config64 {
    //         type Fp = Field64;

    //         const NONRESIDUE: Self::Fp = MontFp!("7");

    //         const FROBENIUS_COEFF_FP2_C1: &'static [Self::Fp] = &[
    //             // Fq(7)**(((q^0) - 1) / 2)
    //             MontFp!("1"),
    //             // Fq(7)**(((q^1) - 1) / 2)
    //             MontFp!("18446744069414584320"),
    //         ];
    //     }

    //     // First absorb 3 Field64 elements:
    //     // - Fp64 has MODULUS_BIT_SIZE = 64
    //     // - bytes_modp(64) = 8
    //     // - 3 scalars × 8 bytes = 24 bytes
    //     // → \0A24foo
    //     let sep = <DomainSeparator as FieldDomainSeparator<Field64>>::add_scalars(
    //         DomainSeparator::new("test-fp"),
    //         3,
    //         "foo",
    //     );

    //     // Then squeeze 1 Field64_2 element:
    //     // - Fp2 has extension_degree = 2 (since it's two Field64 elements)
    //     // - bytes_uniform_modp(64) = 24
    //     // - 2 × 24 = 48 bytes
    //     // → \0S48bar
    //     let sep =
    //         <DomainSeparator as FieldDomainSeparator<Field64_2>>::challenge_scalars(sep, 1, "bar");

    //     // Final byte encoding is:
    //     // - "test-fp" domain label
    //     // - \0A24foo → absorb 24 bytes labeled "foo"
    //     // - \0S48bar → squeeze 48 bytes labeled "bar"
    //     let expected = b"test-fp\0A24foo\0S48bar";
    //     assert_eq!(sep.as_bytes(), expected);
    // }

    // #[test]
    // fn test_add_scalars_babybear() {
    //     // Test absorption of scalars from the base field BabyBear.
    //     // - BabyBear has extension degree = 1
    //     // - Field size: 2^31 - 2^27 + 1 → 31 bits → bytes_modp(31) = 4
    //     // - 2 scalars * 1 * 4 = 8 bytes absorbed
    //     // - "A" prefix indicates absorption in the domain separator
    //     let sep = <DomainSeparator as FieldDomainSeparator<BabyBear>>::add_scalars(
    //         DomainSeparator::new("babybear"),
    //         2,
    //         "foo",
    //     );

    //     let expected = b"babybear\0A8foo";
    //     assert_eq!(sep.as_bytes(), expected);
    // }

    // #[test]
    // fn test_challenge_scalars_babybear() {
    //     // Test squeezing of scalars from the base field BabyBear.
    //     // - BabyBear has extension degree = 1
    //     // - bytes_uniform_modp(31) = 5
    //     // - 3 scalars * 1 * 5 = 15 bytes squeezed
    //     // - "S" prefix indicates squeezing in the domain separator
    //     let sep = <DomainSeparator as FieldDomainSeparator<BabyBear>>::challenge_scalars(
    //         DomainSeparator::new("bb"),
    //         3,
    //         "bar",
    //     );

    //     let expected = b"bb\0S57bar";
    //     assert_eq!(sep.as_bytes(), expected);
    // }

    // #[test]
    // fn test_add_scalars_quadratic_ext_field() {
    //     // Test absorption of scalars from a quadratic extension field (BabyBear2 = Fp2 over BabyBear).
    //     // - Extension degree = 2
    //     // - Base field bits = 31 → bytes_modp(31) = 4
    //     // - 2 scalars * 2 * 4 = 16 bytes absorbed
    //     let sep = <DomainSeparator as FieldDomainSeparator<BabyBear2>>::add_scalars(
    //         DomainSeparator::new("ext"),
    //         2,
    //         "a",
    //     );

    //     let expected = b"ext\0A16a";
    //     assert_eq!(sep.as_bytes(), expected);
    // }

    // #[test]
    // fn test_challenge_scalars_quadratic_ext_field() {
    //     // Test squeezing of scalars from a quadratic extension field (BabyBear2 = Fp2 over BabyBear).
    //     // - Extension degree = 2
    //     // - bytes_uniform_modp(31) = 19
    //     // - 1 scalar * 2 * 19 = 38 bytes squeezed
    //     let sep = <DomainSeparator as FieldDomainSeparator<BabyBear2>>::challenge_scalars(
    //         DomainSeparator::new("ext2"),
    //         1,
    //         "b",
    //     );

    //     let expected = b"ext2\0S38b";
    //     assert_eq!(sep.as_bytes(), expected);
    // }

    // #[test]
    // fn test_add_scalars_quartic_ext_field() {
    //     // Test absorption of scalars from a quartic extension field (BabyBear4 = Fp4 over BabyBear).
    //     // - Extension degree = 4
    //     // - Base field bits = 31 → bytes_modp(31) = 4
    //     // - 2 scalars * 4 * 4 = 32 bytes absorbed
    //     let sep = <DomainSeparator as FieldDomainSeparator<BabyBear4>>::add_scalars(
    //         DomainSeparator::new("ext"),
    //         2,
    //         "a",
    //     );
    //     let expected = b"ext\0A32a";
    //     assert_eq!(sep.as_bytes(), expected);
    // }

    // #[test]
    // fn test_challenge_scalars_quartic_ext_field() {
    //     // Test squeezing of scalars from a quartic extension field (BabyBear4 = Fp4 over BabyBear).
    //     // - Extension degree = 4
    //     // - bytes_uniform_modp(31) = 19
    //     // - 1 scalar * 4 * 19 = 76 bytes squeezed
    //     let sep = <DomainSeparator as FieldDomainSeparator<BabyBear4>>::challenge_scalars(
    //         DomainSeparator::new("ext2"),
    //         1,
    //         "b",
    //     );

    //     let expected = b"ext2\0S76b";
    //     assert_eq!(sep.as_bytes(), expected);
    // }
}
