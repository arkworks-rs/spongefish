#[cfg(feature = "p3-baby-bear")]
pub use p3_baby_bear_poseidon2::{BabyBearPoseidon2_16, BabyBearPoseidon2_24};
#[cfg(feature = "p3-koala-bear")]
pub use p3_koala_bear_poseidon2::{KoalaBearPoseidon2_16, KoalaBearPoseidon2_24};

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
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    impl_permutation!(KoalaBearPoseidon2_16 via Poseidon2KoalaBear<16> over KoalaBear);
    impl_permutation!(KoalaBearPoseidon2_24 via Poseidon2KoalaBear<24> over KoalaBear);
}

#[cfg(feature = "p3-baby-bear")]
mod p3_baby_bear_poseidon2 {
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};

    impl_permutation!(BabyBearPoseidon2_16 via Poseidon2BabyBear<16> over BabyBear);
    impl_permutation!(BabyBearPoseidon2_24 via Poseidon2BabyBear<24> over BabyBear);

    impl Default for crate::BabyBearPoseidon2_24 {
        fn default() -> Self {
            let p2 = p3_poseidon2::Poseidon2::new(
                p3_poseidon2::ExternalLayerConstants::new(
                    p3_baby_bear::BABYBEAR_RC24_EXTERNAL_INITIAL.to_vec(),
                    p3_baby_bear::BABYBEAR_RC24_EXTERNAL_FINAL.to_vec(),
                ),
                p3_baby_bear::BABYBEAR_RC24_INTERNAL.to_vec(),
            );
            Self(p2)
        }
    }

    impl Default for crate::BabyBearPoseidon2_16 {
        fn default() -> Self {
            let p2 = p3_poseidon2::Poseidon2::new(
                p3_poseidon2::ExternalLayerConstants::new(
                    p3_baby_bear::BABYBEAR_RC16_EXTERNAL_INITIAL.to_vec(),
                    p3_baby_bear::BABYBEAR_RC16_EXTERNAL_FINAL.to_vec(),
                ),
                p3_baby_bear::BABYBEAR_RC16_INTERNAL.to_vec(),
            );
            Self(p2)
        }
    }

    // xxx. this implementation does not set the sbox degree correctly?
    // it should be 7, the default sets instead 3.
    // impl Default for crate::KoalaBearPoseidon2_16 {
    //     fn default() -> Self {
    //         let p2_16 = Poseidon2BabyBear::<16>::new_from_rng(rounds_f, rounds_p, rng)
    //     }
    // }

    // impl Default for crate::KoalaBearPoseidon2_16 {
    //     fn default() -> Self {
    //         Self(p3_baby_bear::default_babybear_poseidon2_16())
    //     }
    // }
}
