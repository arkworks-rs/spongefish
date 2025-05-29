//! Implements [`BytesPattern`], [`BytesProver`], and [`BytesVerifier`] when unit is an arkworks prime field.

use ark_ff::{BigInt, Fp, FpConfig, PrimeField};
use zerocopy::IntoBytes;

use crate::{
    codecs::{bytes::BytesCommon, BytesPattern, BytesProver, BytesVerifier},
    transcript::Length,
    UnitCommon, UnitPattern, UnitProver, UnitVerifier,
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
        self.begin_challenge::<[u8]>(label.clone(), Length::Fixed(size))?;
        self.challenge_units("arkworks-field-bytes", size.div_ceil(safe_bytes::<C, N>()))?;
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
        let units = self.challenge_units_vec(
            "arkworks-field-bytes",
            out.len().div_ceil(safe_bytes::<C, N>()),
        )?;
        from_units_out::<C, N>(&units, out);
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
            out.len().div_ceil(safe_bytes::<C, N>()),
        )?;
        from_units_out::<C, N>(&units, out);
        self.end_message::<[u8]>(label, Length::Fixed(out.len()))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use ark_ff::{Field, MontBackend, MontConfig};
    use zeroize::Zeroize;

    use super::*;
    use crate::{
        duplex_sponge::{DuplexSponge, Permutation},
        transcript::{Transcript, TranscriptRecorder},
        DefaultRng, ProverState, VerifierState,
    };

    /// Configuration for the BabyBear field (modulus = 2^31 - 2^27 + 1, generator = 21).
    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearMontConfig;
    pub type BabybearConfig = MontBackend<BabybearMontConfig, 1>;
    pub type BabyBear = Fp<BabybearConfig, 1>;

    fn test_permute(state: &mut [BabyBear; 4]) {
        for r in 0..64 {
            state[0] += BabyBear::from(r);
            state[0] = state[0].pow(&[7]);
            let sum: BabyBear = state.iter().sum();
            state.iter_mut().for_each(|s| *s += sum);
        }
    }

    /// *Insecure* dummy permutation
    #[derive(Clone, Zeroize, Default)]
    pub struct TestPermutation([BabyBear; 4]);

    impl Permutation for TestPermutation {
        type U = BabyBear;
        const N: usize = 4;
        const R: usize = 2;

        fn new(iv: [u8; 32]) -> Self {
            let units = to_units::<BabybearConfig, 1>(&iv);
            Self([units[0], units[1], units[2], units[3]])
        }

        fn permute(&mut self) {
            test_permute(&mut self.0);
        }
    }

    impl AsRef<[BabyBear]> for TestPermutation {
        fn as_ref(&self) -> &[BabyBear] {
            &self.0
        }
    }

    impl AsMut<[BabyBear]> for TestPermutation {
        fn as_mut(&mut self) -> &mut [BabyBear] {
            &mut self.0
        }
    }

    pub type TestSponge = DuplexSponge<TestPermutation>;
    pub type TestProver = ProverState<TestSponge, BabyBear, DefaultRng>;
    pub type TestVerifier<'a> = VerifierState<'a, TestSponge, BabyBear>;

    #[test]
    fn test_packing() {
        assert_eq!(safe_bytes::<BabybearConfig, 1>(), 3);
        assert_eq!(
            to_units::<BabybearConfig, 1>(b"Hello"),
            vec![BabyBear::from(0x6c_6548), BabyBear::from(28524)]
        );
    }

    #[test]
    fn test_all_ops() -> Result<()> {
        let mut pattern = TranscriptRecorder::<BabyBear>::new();
        pattern.begin_protocol::<()>("test all")?;
        pattern.public_bytes("1", 4)?;
        pattern.message_bytes("2", 4)?;
        pattern.challenge_bytes("3", 4)?;
        pattern.end_protocol::<()>("test all")?;
        let pattern = pattern.finalize()?;
        eprintln!("{pattern}");

        let mut prover = TestProver::from(&pattern);
        prover.begin_protocol::<()>("test all")?;
        prover.public_bytes("1", &1_u32.to_le_bytes())?;
        prover.message_bytes("2", &2_u32.to_le_bytes())?;
        assert_eq!(prover.challenge_bytes_array("3")?, [223, 182, 115, 24]);
        prover.end_protocol::<()>("test all")?;
        let proof = prover.finalize()?;
        assert_eq!(hex::encode(&proof), "0200000000000000");

        let mut verifier = TestVerifier::new(pattern.into(), &proof);
        verifier.begin_protocol::<()>("test all")?;
        verifier.public_bytes("1", &1_u32.to_le_bytes())?;
        assert_eq!(verifier.message_bytes_array("2")?, 2_u32.to_le_bytes());
        assert_eq!(verifier.challenge_bytes_array("3")?, [223, 182, 115, 24]);
        verifier.end_protocol::<()>("test all")?;
        verifier.finalize()?;

        Ok(())
    }
}
