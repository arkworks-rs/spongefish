use group::ff::PrimeField;

use super::UnitToField;
use crate::{codecs::bytes_uniform_modp, ProofResult, UnitToBytes};

/// Convert a byte array to a field element.
///
/// This function should be equivalent to arkworks' `PrimeField::from_be_bytes_mod_order`.
/// XXX. A better way to do this?
/// Took less time to implement this than to figure out group's API..
fn from_bytes_mod_order<F: PrimeField>(bytes: &[u8]) -> F {
    let basis = F::from(256);
    bytes
        .iter()
        .fold(F::ZERO, |acc, &b| acc * basis + F::from(u64::from(b)))
}

impl<F, T> UnitToField<F> for T
where
    F: PrimeField,
    T: UnitToBytes,
{
    fn fill_challenge_scalars(&mut self, output: &mut [F]) -> ProofResult<()> {
        let mut buf = vec![0; bytes_uniform_modp(F::NUM_BITS)];

        for o in output {
            self.fill_challenge_bytes(&mut buf)?;
            *o = from_bytes_mod_order(&buf);
        }

        Ok(())
    }
}
