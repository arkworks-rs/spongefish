//! Derive field element as challenge.
//! For field elements as (public) messages or hints, please see [`super::ark_serialize`].
// TODO: When U = F::BasePrimeField we want to use units directly. Unfortunately, this requires
// specialization.

use ark_ff::{Field, PrimeField};

use crate::{
    codecs::bytes,
    transcript::{self, InteractionError, Label, Length, TranscriptError},
};

pub trait Pattern {
    fn challenge_ark_fel<F>(&mut self, label: impl Into<Label>) -> Result<(), TranscriptError>
    where
        F: Field;

    fn challenge_ark_fels<F>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), TranscriptError>
    where
        F: Field;
}

pub trait Common {
    fn challenge_ark_fel<F>(&mut self, label: impl Into<Label>) -> Result<F, InteractionError>
    where
        F: Field;

    fn challenge_ark_fels_out<F>(
        &mut self,
        label: impl Into<Label>,
        out: &mut [F],
    ) -> Result<(), InteractionError>
    where
        F: Field;

    fn challenge_ark_fels_array<F, const N: usize>(
        &mut self,
        label: impl Into<Label>,
    ) -> Result<[F; N], InteractionError>
    where
        F: Field,
    {
        let mut result = [F::ZERO; N];
        self.challenge_ark_fels_out(label, &mut result)?;
        Ok(result)
    }

    fn challenge_ark_fels_vec<F>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<Vec<F>, InteractionError>
    where
        F: Field,
    {
        let mut result = vec![F::ZERO; size];
        self.challenge_ark_fels_out(label, &mut result)?;
        Ok(result)
    }
}

impl<P> Pattern for P
where
    P: transcript::Pattern + bytes::Pattern,
{
    fn challenge_ark_fel<F>(&mut self, label: impl Into<Label>) -> Result<(), TranscriptError>
    where
        F: Field,
    {
        let label = label.into();
        self.begin_challenge::<F>(label.clone(), Length::Scalar)?;
        let base_field_size = bytes_uniform_modp::<F::BasePrimeField>();
        let size = F::extension_degree() as usize * base_field_size;
        self.challenge_bytes("ark-field", size)?;
        self.end_challenge::<F>(label, Length::Scalar)
    }

    fn challenge_ark_fels<F>(
        &mut self,
        label: impl Into<Label>,
        size: usize,
    ) -> Result<(), TranscriptError>
    where
        F: Field,
    {
        let label = label.into();
        self.begin_challenge::<F>(label.clone(), Length::Fixed(size))?;
        let base_field_size = bytes_uniform_modp::<F::BasePrimeField>();
        let field_size = F::extension_degree() as usize * base_field_size;
        self.challenge_bytes("ark-field", size * field_size)?;
        self.end_challenge::<F>(label, Length::Fixed(size))
    }
}

impl<P> Common for P
where
    P: transcript::Common + bytes::Common,
{
    fn challenge_ark_fel<F>(&mut self, label: impl Into<Label>) -> Result<F, InteractionError>
    where
        F: Field,
    {
        let label = label.into();
        self.begin_challenge::<F>(label.clone(), Length::Scalar)?;
        let base_field_size = bytes_uniform_modp::<F::BasePrimeField>();
        let size = F::extension_degree() as usize * base_field_size;
        let bytes = self.challenge_bytes_vec("ark-field", size)?;
        let result = F::from_base_prime_field_elems(
            bytes
                .chunks_exact(base_field_size)
                .map(F::BasePrimeField::from_be_bytes_mod_order),
        )
        .expect("Number of field elements should match extension degree");
        self.end_challenge::<F>(label, Length::Scalar)?;
        Ok(result)
    }

    fn challenge_ark_fels_out<F>(
        &mut self,
        label: impl Into<Label>,
        out: &mut [F],
    ) -> Result<(), InteractionError>
    where
        F: Field,
    {
        let label = label.into();
        self.begin_challenge::<F>(label.clone(), Length::Fixed(out.len()))?;
        let base_field_size = bytes_uniform_modp::<F::BasePrimeField>();
        let field_size = F::extension_degree() as usize * base_field_size;
        let bytes = self.challenge_bytes_vec("ark-field", out.len() * field_size)?;
        for (out, chunk) in out.iter_mut().zip(bytes.chunks_exact(field_size)) {
            *out = F::from_base_prime_field_elems(
                chunk
                    .chunks_exact(base_field_size)
                    .map(F::BasePrimeField::from_be_bytes_mod_order),
            )
            .expect("Number of field elements should match extension degree");
        }
        self.end_challenge::<F>(label, Length::Fixed(out.len()))
    }
}

/// Bytes needed in order to obtain a uniformly distributed random element of `modulus_bits`
const fn bytes_uniform_modp<F>() -> usize
where
    F: PrimeField,
{
    (F::MODULUS_BIT_SIZE as usize + 128) / 8
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::{super::tests::BabyBear, *};
    use crate::{transcript::TranscriptRecorder, ProverState, VerifierState};

    #[test]
    fn test_all_ops() -> Result<()> {
        let mut pattern: TranscriptRecorder = TranscriptRecorder::new();
        pattern.challenge_ark_fel::<BabyBear>("1")?;
        pattern.challenge_ark_fels::<BabyBear>("2", 3)?;
        let pattern = pattern.finalize()?;
        eprintln!("{pattern}");

        let mut prover: ProverState = ProverState::from(&pattern);
        assert_eq!(
            prover.challenge_ark_fel::<BabyBear>("1")?,
            BabyBear::from(303345864)
        );
        assert_eq!(
            prover.challenge_ark_fels_array::<BabyBear, 3>("2")?,
            [
                BabyBear::from(1634935281),
                BabyBear::from(928942326),
                BabyBear::from(42987044)
            ]
        );
        let proof = prover.finalize()?;
        assert_eq!(hex::encode(&proof), "");

        let mut verifier: VerifierState = VerifierState::new(pattern.into(), &proof);
        assert_eq!(
            verifier.challenge_ark_fel::<BabyBear>("1")?,
            BabyBear::from(303345864)
        );
        assert_eq!(
            verifier.challenge_ark_fels_array::<BabyBear, 3>("2")?,
            [
                BabyBear::from(1634935281),
                BabyBear::from(928942326),
                BabyBear::from(42987044)
            ]
        );
        verifier.finalize()?;

        Ok(())
    }
}
