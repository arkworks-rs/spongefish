use ark_ec::{
    short_weierstrass::{Affine as SWAffine, Projective as SWCurve, SWCurveConfig},
    twisted_edwards::{Affine as EdwardsAffine, Projective as EdwardsCurve, TECurveConfig},
    CurveGroup,
};
use ark_ff::{Field, Fp, FpConfig};
use ark_serialize::CanonicalDeserialize;

use super::{FieldToUnitDeserialize, GroupToUnitDeserialize};
use crate::{
    traits::{BytesToUnitDeserialize, UnitTranscript},
    DuplexSpongeInterface, ProofResult, VerifierState,
};

impl<F, H> FieldToUnitDeserialize<F> for VerifierState<'_, H>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn fill_next_scalars(&mut self, output: &mut [F]) -> ProofResult<()> {
        let point_size = F::default().compressed_size();
        let mut buf = vec![0u8; point_size];
        for o in output.iter_mut() {
            self.fill_next_bytes(&mut buf)?;
            *o = F::deserialize_compressed(buf.as_slice())?;
        }
        Ok(())
    }
}

impl<G, H> GroupToUnitDeserialize<G> for VerifierState<'_, H>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
{
    fn fill_next_points(&mut self, output: &mut [G]) -> ProofResult<()> {
        let point_size = G::default().compressed_size();
        let mut buf = vec![0u8; point_size];

        for o in output.iter_mut() {
            self.fill_next_units(&mut buf)?;
            *o = G::deserialize_compressed(buf.as_slice())?;
        }
        Ok(())
    }
}

impl<H, C, const N: usize> FieldToUnitDeserialize<Fp<C, N>> for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn fill_next_scalars(&mut self, output: &mut [Fp<C, N>]) -> crate::ProofResult<()> {
        self.fill_next_units(output)?;
        Ok(())
    }
}

impl<P, H, C, const N: usize> GroupToUnitDeserialize<EdwardsCurve<P>>
    for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    P: TECurveConfig<BaseField = Fp<C, N>>,
{
    fn fill_next_points(&mut self, output: &mut [EdwardsCurve<P>]) -> ProofResult<()> {
        for o in output.iter_mut() {
            let o_affine = EdwardsAffine::deserialize_compressed(&mut self.narg_string)?;
            *o = o_affine.into();
            self.public_units(&[o.x, o.y])?;
        }
        Ok(())
    }
}

impl<P, H, C, const N: usize> GroupToUnitDeserialize<SWCurve<P>> for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    P: SWCurveConfig<BaseField = Fp<C, N>>,
{
    fn fill_next_points(&mut self, output: &mut [SWCurve<P>]) -> ProofResult<()> {
        for o in output.iter_mut() {
            let o_affine = SWAffine::deserialize_compressed(&mut self.narg_string)?;
            *o = o_affine.into();
            self.public_units(&[o.x, o.y])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::G1Projective;
    use ark_curve25519::EdwardsProjective;
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::{AdditiveGroup, Fp64, MontBackend, MontConfig, UniformRand};
    use ark_serialize::CanonicalSerialize;

    use super::*;
    use crate::{
        codecs::arkworks_algebra::{FieldDomainSeparator, GroupDomainSeparator},
        DefaultHash, DomainSeparator,
    };

    /// Custom field for testing: BabyBear
    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearConfig;

    pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;

    #[test]
    fn test_fill_next_scalars_generic_field() {
        use ark_bls12_381::Fr as F;
        let label = "scalar";

        // Sample some field elements and serialize them
        let mut rng = ark_std::test_rng();
        let scalars = [F::rand(&mut rng), F::rand(&mut rng)];
        let mut raw_bytes = Vec::new();
        for s in &scalars {
            s.serialize_compressed(&mut raw_bytes).unwrap();
        }

        // Create a domain separator for absorbing 2 scalars
        let domsep = <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(
            DomainSeparator::<DefaultHash>::new("read"),
            2,
            label,
        );

        let mut verifier = domsep.to_verifier_state(&raw_bytes);

        let mut out = [F::ZERO; 2];
        verifier.fill_next_scalars(&mut out).unwrap();
        assert_eq!(out, scalars, "Deserialized scalars do not match original");
    }

    #[test]
    fn test_fill_next_scalars_fp_unit() {
        let mut rng = ark_std::test_rng();
        let values = [BabyBear::rand(&mut rng), BabyBear::rand(&mut rng)];

        // Serialize scalars
        let mut raw = Vec::new();
        for v in &values {
            v.serialize_compressed(&mut raw).unwrap();
        }

        // Set up domain separator
        let domsep = <DomainSeparator as FieldDomainSeparator<BabyBear>>::add_scalars(
            DomainSeparator::new("fp-unit"),
            2,
            "x",
        );

        let mut verifier = domsep.to_verifier_state(&raw);
        let mut out = [BabyBear::ZERO; 2];
        verifier.fill_next_scalars(&mut out).unwrap();

        assert_eq!(out, values, "Fp unit-based deserialization mismatch");
    }

    #[test]
    fn test_fill_next_points_curve25519_edwards() {
        type G = EdwardsProjective;

        // Sample point and serialize it
        let point = G::generator();
        let mut compressed = Vec::new();
        point
            .into_affine()
            .serialize_compressed(&mut compressed)
            .unwrap();

        // Create domain separator for one point
        let domsep = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::new("curve25519-ed"),
            1,
            "pt",
        );

        // Load verifier with serialized point
        let mut verifier = domsep.to_verifier_state(&compressed);
        let mut out = [G::ZERO];
        verifier.fill_next_points(&mut out).unwrap();

        assert_eq!(
            out[0].into_affine(),
            point.into_affine(),
            "Curve25519 Edwards point deserialization failed"
        );
    }

    #[test]
    fn test_fill_next_points_bls12_sw() {
        type G = G1Projective;

        // Sample point and serialize it
        let point = G::generator();
        let mut compressed = Vec::new();
        point
            .into_affine()
            .serialize_compressed(&mut compressed)
            .unwrap();

        // Create domain separator for one point
        let domsep = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::new("bls12-sw"),
            1,
            "pt",
        );

        let mut verifier = domsep.to_verifier_state(&compressed);
        let mut out = [G::ZERO];
        verifier.fill_next_points(&mut out).unwrap();

        assert_eq!(
            out[0].into_affine(),
            point.into_affine(),
            "SW deserialization failed"
        );
    }

    #[test]
    fn test_fill_next_points_fp_unit_edwards() {
        type G = EdwardsProjective;

        let point = G::generator();
        let mut bytes = Vec::new();
        point
            .into_affine()
            .serialize_compressed(&mut bytes)
            .unwrap();

        let domsep = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::new("curve-edwards-fp"),
            1,
            "pt",
        );

        let mut verifier = domsep.to_verifier_state(&bytes);
        let mut out = [G::ZERO];
        verifier.fill_next_points(&mut out).unwrap();

        assert_eq!(
            out[0].into_affine(),
            point.into_affine(),
            "Edwards point deserialization via Fp failed"
        );
    }

    #[test]
    fn test_fill_next_points_fp_unit_swcurve() {
        type G = G1Projective;

        let point = G::generator();
        let mut bytes = Vec::new();
        point
            .into_affine()
            .serialize_compressed(&mut bytes)
            .unwrap();

        let domsep = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::new("curve-sw-fp"),
            1,
            "pt",
        );

        let mut verifier = domsep.to_verifier_state(&bytes);
        let mut out = [G::ZERO];
        verifier.fill_next_points(&mut out).unwrap();

        assert_eq!(
            out[0].into_affine(),
            point.into_affine(),
            "SW point deserialization via Fp failed"
        );
    }
}
