use ark_ec::CurveGroup;
use ark_ff::{Field, Fp, FpConfig};
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};

use super::{CommonFieldToUnit, CommonGroupToUnit, FieldToUnitSerialize, GroupToUnitSerialize};
use crate::{
    BytesToUnitDeserialize, BytesToUnitSerialize, CommonUnitToBytes, DomainSeparatorMismatch,
    DuplexSpongeInterface, ProofResult, ProverState, Unit, UnitTranscript, VerifierState,
};

impl<F: Field, H: DuplexSpongeInterface, R: RngCore + CryptoRng> FieldToUnitSerialize<F>
    for ProverState<H, u8, R>
{
    fn add_scalars(&mut self, input: &[F]) -> ProofResult<()> {
        let serialized = self.public_scalars(input);
        self.narg_string.extend(serialized?);
        Ok(())
    }
}

impl<
        C: FpConfig<N>,
        H: DuplexSpongeInterface<Fp<C, N>>,
        R: RngCore + CryptoRng,
        const N: usize,
    > FieldToUnitSerialize<Fp<C, N>> for ProverState<H, Fp<C, N>, R>
{
    fn add_scalars(&mut self, input: &[Fp<C, N>]) -> ProofResult<()> {
        self.public_units(input)?;
        for i in input {
            i.serialize_compressed(&mut self.narg_string)?;
        }
        Ok(())
    }
}

impl<G, H, R> GroupToUnitSerialize<G> for ProverState<H, u8, R>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
    Self: CommonGroupToUnit<G, Repr = Vec<u8>>,
{
    fn add_points(&mut self, input: &[G]) -> ProofResult<()> {
        let serialized = self.public_points(input);
        self.narg_string.extend(serialized?);
        Ok(())
    }
}

impl<G, H, R, C: FpConfig<N>, C2: FpConfig<N>, const N: usize> GroupToUnitSerialize<G>
    for ProverState<H, Fp<C, N>, R>
where
    G: CurveGroup<BaseField = Fp<C2, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
    Self: CommonGroupToUnit<G> + FieldToUnitSerialize<G::BaseField>,
{
    fn add_points(&mut self, input: &[G]) -> ProofResult<()> {
        self.public_points(input).map(|_| ())?;
        for i in input {
            i.serialize_compressed(&mut self.narg_string)?;
        }
        Ok(())
    }
}

impl<H, R, C, const N: usize> BytesToUnitSerialize for ProverState<H, Fp<C, N>, R>
where
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
    R: RngCore + CryptoRng,
{
    fn add_bytes(&mut self, input: &[u8]) -> Result<(), DomainSeparatorMismatch> {
        self.public_bytes(input)?;
        self.narg_string.extend(input);
        Ok(())
    }
}

impl<H, C, const N: usize> BytesToUnitDeserialize for VerifierState<'_, H, Fp<C, N>>
where
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn fill_next_bytes(&mut self, input: &mut [u8]) -> Result<(), DomainSeparatorMismatch> {
        u8::read(&mut self.narg_string, input)?;
        self.public_bytes(input)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_curve25519::EdwardsProjective;
    use ark_ec::PrimeGroup;
    use ark_ff::{Fp64, MontBackend, MontConfig, UniformRand};

    use super::*;
    use crate::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitSerialize, GroupDomainSeparator,
        },
        ByteDomainSeparator, DefaultHash, DomainSeparator,
    };

    /// Curve used for tests
    type G = EdwardsProjective;

    /// Configuration for the BabyBear field (modulus = 2^31 - 2^27 + 1, generator = 21).
    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearConfig;

    /// Base field type using the BabyBear configuration.
    pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;

    #[test]
    fn test_add_scalars() {
        // Create a domain separator with a fixed domain label
        let domsep = DomainSeparator::new("test");

        // Append an "absorb scalars" tag to the transcript:
        // - BabyBear has 31-bit modulus ⇒ bytes_modp(31) = 4
        // - 3 scalars * 4 bytes = 12 ⇒ "\0A12com" is added
        let domsep =
            <DomainSeparator as FieldDomainSeparator<BabyBear>>::add_scalars(domsep, 3, "com");

        // Create the prover state from the domain separator
        let mut prover_state = domsep.to_prover_state();

        // Sample 3 random BabyBear field elements to simulate public input
        let mut rng = ark_std::test_rng();
        let (f0, f1, f2) = (
            BabyBear::rand(&mut rng),
            BabyBear::rand(&mut rng),
            BabyBear::rand(&mut rng),
        );

        // Add the scalars to the prover's transcript using the serialize logic
        prover_state.add_scalars(&[f0, f1, f2]).unwrap();

        // Serialize the scalars independently to verify `narg_string` content
        let mut expected_bytes = Vec::new();
        f0.serialize_compressed(&mut expected_bytes).unwrap();
        f1.serialize_compressed(&mut expected_bytes).unwrap();
        f2.serialize_compressed(&mut expected_bytes).unwrap();

        // The `narg_string` in the prover must match the manually serialized data
        assert_eq!(
            prover_state.narg_string, expected_bytes,
            "Transcript serialization mismatch"
        );

        // Repeat with a new prover and same domain separator to test determinism
        let mut prover_state2 = domsep.to_prover_state();
        prover_state2.add_scalars(&[f0, f1, f2]).unwrap();
        assert_eq!(
            prover_state.narg_string, prover_state2.narg_string,
            "Transcript encoding should be deterministic for same inputs"
        );
    }

    #[test]
    fn test_add_scalars_u8_unit() {
        // Construct a domain separator that absorbs 2 field elements
        let domsep = DomainSeparator::new("test-add-scalars-u8");
        let domsep = <DomainSeparator as FieldDomainSeparator<Fr>>::add_scalars(domsep, 2, "com");

        // Create prover state from domain separator
        let mut prover = domsep.to_prover_state();

        // Use two deterministic values for test
        let f0 = Fr::from(5u64);
        let f1 = Fr::from(42u64);

        // Add the scalars to the prover's transcript
        prover.add_scalars(&[f0, f1]).unwrap();

        // Serialize the expected bytes directly
        let mut expected = Vec::new();
        f0.serialize_compressed(&mut expected).unwrap();
        f1.serialize_compressed(&mut expected).unwrap();

        // Assert transcript encoding is correct
        assert_eq!(prover.narg_string, expected);
    }

    #[test]
    fn test_add_points_u8_unit() {
        // Use ark_curve25519 curve (compressed point = 32 bytes)
        let domsep = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::new("curve25519"),
            1,
            "pt",
        );

        let mut prover = domsep.to_prover_state();
        let point = G::generator();

        // Add the point to the prover's transcript
        prover.add_points(&[point]).unwrap();

        assert!(!prover.narg_string.is_empty());
    }

    #[test]
    fn test_add_points_fp_unit() {
        let domsep = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::new("curve-bb"),
            1,
            "pt",
        );

        let mut prover = domsep.to_prover_state();
        let point = G::generator();

        // This triggers `GroupToUnitSerialize<G> for ProverState<H, Fp<C, N>, R>`
        prover.add_points(&[point]).unwrap();

        // Expect compressed x/y coordinates in `narg_string`
        let mut expected = Vec::new();
        point.serialize_compressed(&mut expected).unwrap();
        assert_eq!(prover.narg_string, expected);
    }

    #[test]
    fn test_add_bytes_fp_unit() {
        let input = b"hello world!";

        // Domain separator that expects 12 bytes to be absorbed
        let domsep: DomainSeparator<DefaultHash, u8> = DomainSeparator::new("test-add-bytes-fp");
        let domsep = domsep.add_bytes(12, "com");

        let mut prover = domsep.to_prover_state();

        // Add the bytes to the prover's transcript
        prover.add_bytes(input).unwrap();

        // The bytes should be directly copied into the transcript `narg_string`
        assert_eq!(prover.narg_string, input);
    }

    #[test]
    fn test_fill_next_bytes_fp_unit() {
        let input = b"secret-msg";

        // Set up prover to absorb input bytes and record them in narg_string
        let domsep: DomainSeparator<DefaultHash, u8> = DomainSeparator::new("read-bytes");
        let domsep = domsep.add_bytes(input.len(), "msg");
        let mut prover = domsep.to_prover_state();
        prover.add_bytes(input).unwrap();

        // Reconstruct verifier state from same domain + transcript
        let mut verifier = domsep.to_verifier_state(&prover.narg_string);

        // Read the bytes from the verifier state
        let mut buf = [0u8; 10];
        verifier.fill_next_bytes(&mut buf).unwrap();

        assert_eq!(buf, *input);
    }
}
