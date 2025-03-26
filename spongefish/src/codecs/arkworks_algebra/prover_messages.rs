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
