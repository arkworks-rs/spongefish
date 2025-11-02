#[cfg(feature = "ascon")]
pub use ascon::Ascon12;
#[cfg(feature = "keccak")]
pub use keccak::KeccakF1600;

#[cfg(feature = "ascon")]
mod ascon {

    #[derive(Clone, Debug)]
    pub struct Ascon12;
    use crate::duplex_sponge::Permutation;

    impl Permutation<40> for Ascon12 {
        type U = u8;

        fn permute(&self, state: &[u8; 40]) -> [u8; 40] {
            let mut state = ascon::State::from(state);
            state.permute_12();
            state.as_bytes()
        }
    }
}

#[cfg(feature = "keccak")]
mod keccak {
    use core::fmt::Debug;

    use crate::duplex_sponge::Permutation;

    /// Keccak permutation internal state: 25 64-bit words,
    /// or equivalently 200 bytes in little-endian order.
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct KeccakF1600;

    /// Make sure that we're compiling in a platform where
    /// the use of transmute for keccak evaluations is OK.
    const _: () = assert!(core::mem::size_of::<u64>() == 8 * core::mem::size_of::<u8>());

    impl Permutation<{ 136 + 64 }> for KeccakF1600 {
        type U = u8;

        fn permute(&self, state: &[u8; 200]) -> [u8; 200] {
            let mut new_state = state.clone();
            self.permute_mut(&mut new_state);
            new_state
        }

        fn permute_mut(&self, state: &mut [Self::U; 200]) {
            unsafe { keccak::f1600(core::mem::transmute(state)) };
        }
    }
}
