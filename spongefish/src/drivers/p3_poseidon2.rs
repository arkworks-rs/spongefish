#[cfg(feature = "p3-baby-bear")]
pub use p3_baby_bear_poseidon2::{BabyBearPoseidon2_16, BabyBearPoseidon2_24};

#[cfg(feature = "p3-koala-bear")]
#[cfg(feature = "p3-koala-bear")]
#[allow(unused)]
mod p3_koala_bear_poseidon2 {
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};

    use crate::Unit;

    /// Hack in order to keep track of the state while at the same time
    /// holding ga reference to the Poseidon2 constants used.
    #[derive(Clone)]
    pub struct KoalaBearPoseidon2_16 {
        state: [KoalaBear; 16],
        poseidon2: Poseidon2KoalaBear<16>,
    }

    #[derive(Clone)]
    pub struct KoalaBearPoseidon2_24 {
        state: [KoalaBear; 24],
        poseidon2: Poseidon2KoalaBear<24>,
    }

    impl AsMut<[KoalaBear]> for KoalaBearPoseidon2_16 {
        fn as_mut(&mut self) -> &mut [KoalaBear] {
            self.state.as_mut_slice()
        }
    }

    impl AsMut<[KoalaBear]> for KoalaBearPoseidon2_24 {
        fn as_mut(&mut self) -> &mut [KoalaBear] {
            self.state.as_mut_slice()
        }
    }

    impl AsRef<[KoalaBear]> for KoalaBearPoseidon2_16 {
        fn as_ref(&self) -> &[KoalaBear] {
            self.state.as_ref()
        }
    }

    impl AsRef<[KoalaBear]> for KoalaBearPoseidon2_24 {
        fn as_ref(&self) -> &[KoalaBear] {
            self.state.as_ref()
        }
    }

    // xxx available in the next release of p3
    // impl crate::duplex_sponge::Permutation for KoalaBearPoseidon2_16 {
    //     type U = KoalaBear;
    //     const WIDTH: usize = 16;

    //     fn new() -> Self {
    //         let rng=
    //         Self {
    //             poseidon2: p3_koala_bear::default_koalabear_poseidon2_24(),
    //             state: [Unit::ZERO; Self::WIDTH]
    //         }
    //     }

    //     #[inline]
    //     fn permute(&mut self) {
    //         let new_state = p3_symmetric::Permutation::permute(&self.poseidon2, self.state);
    //         self.state = new_state;
    //     }
    // }

    //     impl crate::duplex_sponge::Permutation for KoalaBearPoseidon2_24 {
    //     type U = KoalaBear;
    //     const WIDTH: usize = 24;

    //     fn new() -> Self {
    //         Self {
    //             poseidon2: p3_koala_bear::default_koalabear_poseidon2_24(),
    //             state: [Unit::ZERO; Self::WIDTH]
    //         }
    //     }

    //     #[inline]
    //     fn permute(&mut self) {
    //         let new_state = p3_symmetric::Permutation::permute(&self.poseidon2, self.state);
    //         self.state = new_state;
    //     }
    // }
}

#[cfg(feature = "p3-baby-bear")]
mod p3_baby_bear_poseidon2 {
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};

    use crate::Unit;

    /// Hack in order to keep track of the state while at the same time
    /// holding a reference to the Poseidon2 constants used.
    #[derive(Clone)]
    pub struct BabyBearPoseidon2_16 {
        state: [BabyBear; 16],
        poseidon2: Poseidon2BabyBear<16>,
    }

    #[derive(Clone)]
    pub struct BabyBearPoseidon2_24 {
        state: [BabyBear; 24],
        poseidon2: Poseidon2BabyBear<24>,
    }

    impl AsMut<[BabyBear]> for BabyBearPoseidon2_16 {
        fn as_mut(&mut self) -> &mut [BabyBear] {
            self.state.as_mut_slice()
        }
    }

    impl AsMut<[BabyBear]> for BabyBearPoseidon2_24 {
        fn as_mut(&mut self) -> &mut [BabyBear] {
            self.state.as_mut_slice()
        }
    }

    impl AsRef<[BabyBear]> for BabyBearPoseidon2_16 {
        fn as_ref(&self) -> &[BabyBear] {
            self.state.as_ref()
        }
    }

    impl AsRef<[BabyBear]> for BabyBearPoseidon2_24 {
        fn as_ref(&self) -> &[BabyBear] {
            self.state.as_ref()
        }
    }

    impl crate::duplex_sponge::Permutation for BabyBearPoseidon2_16 {
        type U = BabyBear;
        const WIDTH: usize = 16;

        fn new() -> Self {
            Self {
                poseidon2: p3_baby_bear::default_babybear_poseidon2_16(),
                state: [Unit::ZERO; Self::WIDTH],
            }
        }

        #[inline]
        fn permute(&mut self) {
            let new_state = p3_symmetric::Permutation::permute(&self.poseidon2, self.state);
            self.state = new_state;
        }
    }

    impl crate::duplex_sponge::Permutation for BabyBearPoseidon2_24 {
        type U = BabyBear;
        const WIDTH: usize = 24;

        fn new() -> Self {
            Self {
                poseidon2: p3_baby_bear::default_babybear_poseidon2_24(),
                state: [Unit::ZERO; Self::WIDTH],
            }
        }

        #[inline]
        fn permute(&mut self) {
            let new_state = p3_symmetric::Permutation::permute(&self.poseidon2, self.state);
            self.state = new_state;
        }
    }
}
