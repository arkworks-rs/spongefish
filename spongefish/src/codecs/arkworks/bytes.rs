//! Implements [`BytesPattern`], [`BytesProver`], and [`BytesVerifier`] when unit is an arkworks prime field.

use ark_ff::{BigInt, Fp, FpConfig, PrimeField};
use zerocopy::IntoBytes;

use crate::{
    codecs::{bytes::BytesCommon, BytesPattern, BytesProver, BytesVerifier},
    transcript::Length,
    UnitCommon, UnitPattern, UnitProver, UnitVerifier,
};

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
        self.public_units("arkworks-field-bytes", size.div_ceil(pack_bytes::<C, N>()))?;
        self.end_public::<[u8]>(label, Length::Fixed(size))
    }

    fn message_bytes(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        size: usize,
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.message_units("arkworks-field-bytes", size.div_ceil(pack_bytes::<C, N>()))?;
        self.end_message::<[u8]>(label, Length::Fixed(size))
    }

    fn challenge_bytes(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        size: usize,
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_challenge::<[u8]>(label.clone(), Length::Fixed(size))?;
        let bytes_per_element = random_bytes_in_random_modp(C::MODULUS);
        // TODO: Combine multiple elements to get enough entropy.
        assert!(
            bytes_per_element > 0,
            "Field too small to safely extract challenge bytes from."
        );
        self.challenge_units("arkworks-field-bytes", size.div_ceil(bytes_per_element))?;
        self.end_challenge::<[u8]>(label, Length::Fixed(size))
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
        let bytes_per_element = random_bytes_in_random_modp(C::MODULUS);
        let units = self.challenge_units_vec(
            "arkworks-field-bytes",
            out.len().div_ceil(bytes_per_element),
        )?;
        for (unit, chunk) in units.iter().zip(out.chunks_mut(bytes_per_element)) {
            let limbs = unit.into_bigint().0;
            chunk.copy_from_slice(&limbs.as_bytes()[..chunk.len()]);
        }
        self.end_challenge::<[u8]>(label, Length::Fixed(out.len()))
    }
}

impl<P, C, const N: usize> BytesProver<Fp<C, N>> for P
where
    P: UnitProver<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn message_bytes(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        value: &[u8],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(value.len()))?;
        self.message_units("arkworks-field-bytes", &to_units(value))?;
        self.end_message::<[u8]>(label, Length::Fixed(value.len()))
    }
}

impl<'a, P, C, const N: usize> BytesVerifier<'a, Fp<C, N>> for P
where
    P: UnitVerifier<'a, Fp<C, N>>,
    C: FpConfig<N>,
{
    fn message_bytes_out(
        &mut self,
        label: impl Into<crate::transcript::Label>,
        out: &mut [u8],
    ) -> Result<(), Self::Error> {
        let label = label.into();
        self.begin_message::<[u8]>(label.clone(), Length::Fixed(out.len()))?;
        let units = self.message_units_vec(
            "arkworks-field-bytes",
            out.len().div_ceil(pack_bytes::<C, N>()),
        )?;
        from_units_out::<C, N>(&units, out);
        self.end_message::<[u8]>(label, Length::Fixed(out.len()))
    }
}

/// Number of bytes that can unambiguously be packed into a field element.
pub(super) const fn pack_bytes<C: FpConfig<N>, const N: usize>() -> usize {
    let safe_bits = C::MODULUS.const_num_bits() - 1;
    assert!(safe_bits >= 8, "Can not safely pack bytes into this field.");
    (safe_bits / 8) as usize
}

pub(super) fn to_units<C: FpConfig<N>, const N: usize>(bytes: &[u8]) -> Vec<Fp<C, N>> {
    bytes
        .chunks(pack_bytes::<C, N>())
        .map(|chunk| {
            let mut limbs = [0_u64; N];
            limbs.as_mut_bytes()[..chunk.len()].copy_from_slice(chunk);
            Fp::from_bigint(BigInt(limbs)).expect("packing can not produce unreduced elements")
        })
        .collect::<Vec<_>>()
}

pub(super) fn from_units_out<C: FpConfig<N>, const N: usize>(units: &[Fp<C, N>], out: &mut [u8]) {
    for (unit, chunk) in units.iter().zip(out.chunks_mut(pack_bytes::<C, N>())) {
        let limbs = unit.into_bigint().0;
        chunk.copy_from_slice(&limbs.as_bytes()[..chunk.len()]);
    }
}

/// Number of uniformly random bytes of in a uniformly-distributed element in `[0, b)`.
///
/// This function returns the maximum n for which
/// `Uniform([b]) mod 2^n`
/// and
/// `Uniform([2^n])`
/// are statistically indistinguishable.
/// Given \(b = q 2^n + r\) the statistical distance
/// is \(\frac{2r}{ab}(a-r)\).
// TODO: For small fields this will always return zero. Instead we should combine multiple elements
// to get enough combined entropy. For this we need to find k such that p^k > 2^{8*k + 128} and then
// compute sum_i f_i * p^i mod 2^{8*k} to get random bytes.
fn random_bits_in_random_modp<const N: usize>(b: BigInt<N>) -> usize {
    use ark_ff::{BigInt, BigInteger};
    // XXX. is it correct to have num_bits+1 here?
    for n in (0..=b.num_bits()).rev() {
        // compute the remainder of b by 2^n
        let r_bits = &b.to_bits_le()[..n as usize];
        let r = BigInt::<N>::from_bits_le(r_bits);
        let log2_a_minus_r = r_bits.iter().rev().skip_while(|&&bit| bit).count() as u32;
        if b.num_bits() + n - 1 - r.num_bits() - log2_a_minus_r >= 128 {
            return n as usize;
        }
    }
    0
}

/// Same as above, but for bytes
fn random_bytes_in_random_modp<const N: usize>(modulus: BigInt<N>) -> usize {
    random_bits_in_random_modp(modulus) / 8
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::{
        super::tests::{BabyBear, BabybearConfig, TestProver, TestVerifier},
        *,
    };
    use crate::transcript::{Transcript, TranscriptRecorder};

    #[test]
    fn test_packing() {
        assert_eq!(pack_bytes::<BabybearConfig, 1>(), 3);
        assert_eq!(
            to_units::<BabybearConfig, 1>(b"Hello"),
            vec![BabyBear::from(0x6c_6548), BabyBear::from(28524)]
        );
        assert_eq!(random_bits_in_random_modp(BabybearConfig::MODULUS), 0);
        assert_eq!(random_bits_in_random_modp(ark_pallas::Fr::MODULUS), 254); // Is this right?
    }

    #[test]
    fn test_all_ops_babybear() -> Result<()> {
        let mut pattern = TranscriptRecorder::<BabyBear>::new();
        pattern.begin_protocol::<()>("test all")?;
        pattern.public_bytes("1", 4)?;
        pattern.message_bytes("2", 4)?;
        // pattern.challenge_bytes("3", 4)?;
        pattern.end_protocol::<()>("test all")?;
        let pattern = pattern.finalize()?;
        eprintln!("{pattern}");

        let mut prover = TestProver::from(&pattern);
        prover.begin_protocol::<()>("test all")?;
        prover.public_bytes("1", &1_u32.to_le_bytes())?;
        prover.message_bytes("2", &2_u32.to_le_bytes())?;
        // assert_eq!(prover.challenge_bytes_array("3")?, [223, 182, 115, 24]);
        prover.end_protocol::<()>("test all")?;
        let proof = prover.finalize()?;
        assert_eq!(hex::encode(&proof), "0200000000000000");

        let mut verifier = TestVerifier::new(pattern.into(), &proof);
        verifier.begin_protocol::<()>("test all")?;
        verifier.public_bytes("1", &1_u32.to_le_bytes())?;
        assert_eq!(verifier.message_bytes_array("2")?, 2_u32.to_le_bytes());
        // assert_eq!(verifier.challenge_bytes_array("3")?, [223, 182, 115, 24]);
        verifier.end_protocol::<()>("test all")?;
        verifier.finalize()?;

        Ok(())
    }
}
