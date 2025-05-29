//! Implements [`BytesPattern`], [`BytesProver`], and [`BytesVerifier`] when unit is an arkworks prime field.

use ark_ff::{BigInt, Fp, FpConfig, PrimeField};
use zerocopy::IntoBytes;

use crate::{
    codecs::{bytes::BytesCommon, BytesPattern},
    transcript::Length,
    UnitCommon, UnitPattern,
};

/// Number of bytes that can unambiguously be packed into a field element.
const fn safe_bytes<C: FpConfig<N>, const N: usize>() -> usize {
    let safe_bits = C::MODULUS.const_num_bits() - 1;
    assert!(safe_bits >= 8, "Can not safely pack bytes into this field.");
    (safe_bits / 8) as usize
}

fn to_units<C: FpConfig<N>, const N: usize>(bytes: &[u8]) -> Vec<Fp<C, N>> {
    bytes
        .chunks(safe_bytes::<C, N>())
        .map(|chunk| {
            let mut limbs = [0_u64; N];
            limbs.as_mut_bytes()[..chunk.len()].copy_from_slice(chunk);
            Fp::from_bigint(BigInt(limbs)).expect("packing can not produce unreduced elements")
        })
        .collect::<Vec<_>>()
}

fn from_units_out<C: FpConfig<N>, const N: usize>(units: &[Fp<C, N>], out: &mut [u8]) {
    for (unit, chunk) in units.iter().zip(out.chunks_mut(safe_bytes::<C, N>())) {
        let limbs = unit.into_bigint().0;
        chunk.copy_from_slice(&limbs.as_bytes()[..chunk.len()]);
    }
}

impl<P, C, const N: usize> BytesPattern<Fp<C, N>> for P
where
    P: UnitPattern<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn public_bytes(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        size: usize,
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_public::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.public_units("arkworks-field-bytes", size.div_ceil(safe_bytes::<C, N>()))?;
        self.end_public::<[u8]>(label, Length::Fixed(size))
    }

    fn message_bytes(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        size: usize,
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.message_units("arkworks-field-bytes", size.div_ceil(safe_bytes::<C, N>()))?;
        self.end_message::<[u8]>(label, Length::Fixed(size))
    }

    fn challenge_bytes(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        size: usize,
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.challenge_units("arkworks-field-bytes", size.div_ceil(safe_bytes::<C, N>()))?;
        self.end_message::<[u8]>(label, Length::Fixed(size))
    }
}

impl<P, C, const N: usize> BytesCommon<Fp<C, N>> for P
where
    P: UnitCommon<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn public_bytes(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &[u8],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_public::<[u8]>(label.clone(), Length::Fixed(value.len()))?;
        self.public_units("arkworks-field-bytes", &to_units(value))?;
        self.end_public::<[u8]>(label, Length::Fixed(value.len()))
    }

    fn challenge_bytes_out(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        out: &mut [u8],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_challenge::<[u8]>(label.clone(), Length::Fixed(out.len()))?;
        let units = self.challenge_units_vec(
            "arkworks-field-bytes",
            out.len().div_ceil(safe_bytes::<C, N>()),
        )?;
        from_units_out::<C, N>(&units, out);
        self.end_challenge::<[u8]>(label, Length::Fixed(out.len()))
    }
}
