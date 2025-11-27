#[cfg(feature = "p3-baby-bear")]
pub use p3_baby_bear_poseidon2::{BabyBearPoseidon2_16, BabyBearPoseidon2_24};
#[cfg(feature = "p3-koala-bear")]
pub use p3_koala_bear_poseidon2::{KoalaBearPoseidon2_16, KoalaBearPoseidon2_24};
#[cfg(feature = "risc0-zkp")]
pub use risc0_poseidon2::RiscZeroBabyBearPoseidon2_24;

#[cfg(feature = "risc0-zkp")]
mod risc0_poseidon2;

/// Wrapper on Poseidon2KoalaBear of width 16.
#[cfg(any(feature = "p3-koala-bear", feature = "p3-baby-bear"))]
macro_rules! impl_permutation {
    ($name:ident via $permutation:ident<$width:literal> over $field:ty) => {
        #[derive(Clone)]
        pub struct $name($permutation<$width>);

        impl From<$permutation<$width>> for $name {
            fn from(inner: $permutation<$width>) -> Self {
                Self(inner)
            }
        }

        impl spongefish::Permutation<$width> for $name
        where
            $permutation<$width>: p3_symmetric::Permutation<[$field; $width]>,
        {
            type U = $field;

            fn permute(&self, state: &[Self::U; $width]) -> [Self::U; $width] {
                p3_symmetric::Permutation::permute(&self.0, state.clone())
            }

            fn permute_mut(&self, state: &mut [Self::U; $width]) {
                p3_symmetric::Permutation::permute_mut(&self.0, state);
            }
        }
    };
}

#[cfg(feature = "p3-koala-bear")]
#[allow(unused)]
mod p3_koala_bear_poseidon2 {
    use p3_koala_bear::{
        KoalaBear, Poseidon2ExternalLayerKoalaBear, Poseidon2InternalLayerKoalaBear,
        Poseidon2KoalaBear, KOALABEAR_RC16_EXTERNAL_FINAL, KOALABEAR_RC16_EXTERNAL_INITIAL,
        KOALABEAR_RC16_INTERNAL,
    };

    type SpongefishPoseidon2KoalaBear<const WIDTH: usize> = p3_poseidon2::Poseidon2<
        KoalaBear,
        Poseidon2ExternalLayerKoalaBear<WIDTH>,
        Poseidon2InternalLayerKoalaBear<WIDTH>,
        WIDTH,
        7,
    >;

    impl_permutation!(KoalaBearPoseidon2_16 via Poseidon2KoalaBear<16> over KoalaBear);
    impl_permutation!(KoalaBearPoseidon2_24 via Poseidon2KoalaBear<24> over KoalaBear);

    impl Default for crate::KoalaBearPoseidon2_16 {
        fn default() -> Self {
            let p2 = p3_poseidon2::Poseidon2::new(
                p3_poseidon2::ExternalLayerConstants::new(
                    KOALABEAR_RC16_EXTERNAL_INITIAL.to_vec(),
                    KOALABEAR_RC16_EXTERNAL_FINAL.to_vec(),
                ),
                KOALABEAR_RC16_INTERNAL.to_vec(),
            );
            Self(p2)
        }
    }
}

#[cfg(feature = "p3-baby-bear")]
mod p3_baby_bear_poseidon2 {
    use p3_baby_bear::{
        BabyBear, Poseidon2ExternalLayerBabyBear, Poseidon2InternalLayerBabyBear,
        BABYBEAR_RC16_EXTERNAL_FINAL, BABYBEAR_RC16_EXTERNAL_INITIAL, BABYBEAR_RC16_INTERNAL,
        BABYBEAR_RC24_EXTERNAL_FINAL, BABYBEAR_RC24_EXTERNAL_INITIAL, BABYBEAR_RC24_INTERNAL,
    };

    type SpongefishPoseidon2BabyBear<const WIDTH: usize> = p3_poseidon2::Poseidon2<
        BabyBear,
        Poseidon2ExternalLayerBabyBear<WIDTH>,
        Poseidon2InternalLayerBabyBear<WIDTH>,
        WIDTH,
        7,
    >;

    impl_permutation!(BabyBearPoseidon2_16 via SpongefishPoseidon2BabyBear<16> over BabyBear);
    impl_permutation!(BabyBearPoseidon2_24 via SpongefishPoseidon2BabyBear<24> over BabyBear);

    impl Default for crate::BabyBearPoseidon2_24 {
        fn default() -> Self {
            let p2 = p3_poseidon2::Poseidon2::new(
                p3_poseidon2::ExternalLayerConstants::new(
                    BABYBEAR_RC24_EXTERNAL_INITIAL.to_vec(),
                    BABYBEAR_RC24_EXTERNAL_FINAL.to_vec(),
                ),
                BABYBEAR_RC24_INTERNAL.to_vec(),
            );
            Self(p2)
        }
    }

    impl Default for crate::BabyBearPoseidon2_16 {
        fn default() -> Self {
            let p2 = p3_poseidon2::Poseidon2::new(
                p3_poseidon2::ExternalLayerConstants::new(
                    BABYBEAR_RC16_EXTERNAL_INITIAL.to_vec(),
                    BABYBEAR_RC16_EXTERNAL_FINAL.to_vec(),
                ),
                BABYBEAR_RC16_INTERNAL.to_vec(),
            );
            Self(p2)
        }
    }
}
