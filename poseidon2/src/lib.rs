#[cfg(feature = "p3-baby-bear")]
pub use p3_baby_bear_poseidon2::{BabyBearPoseidon2_16, BabyBearPoseidon2_24};
#[cfg(feature = "p3-koala-bear")]
pub use p3_koala_bear_poseidon2::{KoalaBearPoseidon2_16, KoalaBearPoseidon2_24};

/// Wrapper on Poseidon2KoalaBear of width 16.

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
}
