//! Derive field element as challenge.
//! For field elements as (public) messages or hints, please see [`super::ark_serialize`].
// TODO: When U = F::BasePrimeField we want to use units directly. Unfortunately, this requires
// specialization.

use ark_ff::{Field, PrimeField};

use crate::{
    codecs::bytes,
    transcript::{self, Label, Length},
    VerifierError,
};

pub trait Pattern {
    fn public_ark_field<F: Field>(&mut self, label: Label);
    fn public_ark_field_many<F: Field>(&mut self, label: Label, count: usize);
    fn message_ark_field<F: Field>(&mut self, label: Label);
    fn message_ark_field_many<F: Field>(&mut self, label: Label, count: usize);
    fn challenge_ark_field<F: Field>(&mut self, label: Label);
    fn challenge_ark_field_many<F: Field>(&mut self, label: Label, count: usize);
}

pub trait Common {
    fn public_ark_field<F: Field>(&mut self, label: Label, value: F) -> F;

    fn public_ark_field_slice<F: Field>(&mut self, label: Label, values: &[F]);

    fn challenge_ark_field<F: Field>(&mut self, label: Label) -> F;

    fn challenge_ark_field_out<F: Field>(&mut self, label: Label, out: &mut [F]);

    fn challenge_ark_field_array<F: Field, const N: usize>(&mut self, label: Label) -> [F; N] {
        let mut result = [F::ZERO; N];
        self.challenge_ark_field_out(label, &mut result);
        result
    }

    fn challenge_ark_field_vec<F: Field>(&mut self, label: Label, size: usize) -> Vec<F> {
        let mut result = vec![F::ZERO; size];
        self.challenge_ark_field_out(label, &mut result);
        result
    }
}

pub trait Prover: Common {
    fn message_ark_field<F: Field>(&mut self, label: Label, value: F) -> F;

    fn message_ark_field_slice<F: Field>(&mut self, label: Label, values: &[F]);
}

pub trait Verifier: Common {
    fn message_ark_field<F: Field>(&mut self, label: Label) -> Result<F, VerifierError>;

    fn message_ark_field_out<F: Field>(
        &mut self,
        label: Label,
        out: &mut [F],
    ) -> Result<(), VerifierError>;

    fn message_ark_field_array<F: Field, const N: usize>(
        &mut self,
        label: Label,
    ) -> Result<[F; N], VerifierError> {
        let mut result = [F::ZERO; N];
        self.message_ark_field_out(label, &mut result)?;
        Ok(result)
    }

    fn message_ark_field_vec<F: Field>(
        &mut self,
        label: Label,
        size: usize,
    ) -> Result<Vec<F>, VerifierError> {
        let mut result = vec![F::ZERO; size];
        self.message_ark_field_out(label, &mut result)?;
        Ok(result)
    }
}

impl<P> Pattern for P
where
    P: transcript::Pattern + bytes::Pattern,
{
    fn challenge_ark_field<F: Field>(&mut self, label: Label) {
        self.begin_challenge::<F>(label, Length::Scalar);
        let base_field_size = bytes_uniform_modp::<F::BasePrimeField>();
        let size = F::extension_degree() as usize * base_field_size;
        self.challenge_bytes("ark-field", size);
        self.end_challenge::<F>(label, Length::Scalar);
    }

    fn challenge_ark_field_many<F: Field>(&mut self, label: Label, count: usize) {
        self.begin_challenge::<F>(label, Length::Fixed(count));
        let base_field_size = bytes_uniform_modp::<F::BasePrimeField>();
        let field_size = F::extension_degree() as usize * base_field_size;
        self.challenge_bytes("ark-field", count * field_size);
        self.end_challenge::<F>(label, Length::Fixed(count));
    }

    fn public_ark_field<F: Field>(&mut self, label: Label) {
        todo!()
    }

    fn public_ark_field_many<F: Field>(&mut self, label: Label, count: usize) {
        todo!()
    }

    fn message_ark_field<F: Field>(&mut self, label: Label) {
        todo!()
    }

    fn message_ark_field_many<F: Field>(&mut self, label: Label, count: usize) {
        todo!()
    }
}

impl<P> Common for P
where
    P: transcript::Common + bytes::Common,
{
    fn challenge_ark_field<F: Field>(&mut self, label: Label) -> F {
        self.begin_challenge::<F>(label, Length::Scalar);
        let base_field_size = bytes_uniform_modp::<F::BasePrimeField>();
        let size = F::extension_degree() as usize * base_field_size;
        let bytes = self.challenge_bytes_vec("ark-field", size);
        let result = F::from_base_prime_field_elems(
            bytes
                .chunks_exact(base_field_size)
                .map(F::BasePrimeField::from_be_bytes_mod_order),
        )
        .expect("Number of field elements should match extension degree");
        self.end_challenge::<F>(label, Length::Scalar);
        result
    }

    fn challenge_ark_field_out<F: Field>(&mut self, label: Label, out: &mut [F]) {
        self.begin_challenge::<F>(label, Length::Fixed(out.len()));
        let base_field_size = bytes_uniform_modp::<F::BasePrimeField>();
        let field_size = F::extension_degree() as usize * base_field_size;
        let bytes = self.challenge_bytes_vec("ark-field", out.len() * field_size);
        for (out, chunk) in out.iter_mut().zip(bytes.chunks_exact(field_size)) {
            *out = F::from_base_prime_field_elems(
                chunk
                    .chunks_exact(base_field_size)
                    .map(F::BasePrimeField::from_be_bytes_mod_order),
            )
            .expect("Number of field elements should match extension degree");
        }
        self.end_challenge::<F>(label, Length::Fixed(out.len()));
    }

    fn public_ark_field<F: Field>(&mut self, label: Label, value: F) -> F {
        todo!()
    }

    fn public_ark_field_slice<F: Field>(&mut self, label: Label, values: &[F]) {
        todo!()
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
    use crate::{transcript::PatternState, ProverState, VerifierState};

    #[test]
    fn test_all_ops() -> Result<()> {
        let mut pattern: PatternState = PatternState::new();
        pattern.challenge_ark_field::<BabyBear>("1");
        pattern.challenge_ark_field_many::<BabyBear>("2", 3);
        let pattern = pattern.finalize();
        eprintln!("{pattern}");

        let mut prover: ProverState = ProverState::from(&pattern);
        assert_eq!(
            prover.challenge_ark_field::<BabyBear>("1"),
            BabyBear::from(303345864)
        );
        assert_eq!(
            prover.challenge_ark_field_array::<BabyBear, 3>("2"),
            [
                BabyBear::from(1634935281),
                BabyBear::from(928942326),
                BabyBear::from(42987044)
            ]
        );
        let proof = prover.finalize();
        assert_eq!(hex::encode(&proof), "");

        let mut verifier: VerifierState = VerifierState::new(pattern.into(), &proof);
        assert_eq!(
            verifier.challenge_ark_field::<BabyBear>("1"),
            BabyBear::from(303345864)
        );
        assert_eq!(
            verifier.challenge_ark_field_array::<BabyBear, 3>("2"),
            [
                BabyBear::from(1634935281),
                BabyBear::from(928942326),
                BabyBear::from(42987044)
            ]
        );
        verifier.finalize();

        Ok(())
    }
}
