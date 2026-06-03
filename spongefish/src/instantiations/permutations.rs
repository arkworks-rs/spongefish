#[cfg(feature = "ascon")]
pub use ascon::Ascon12;
#[cfg(feature = "keccak")]
pub use keccak::KeccakF1600;

#[cfg(any(feature = "ascon", feature = "keccak"))]
const _: () = assert!(cfg!(target_endian = "little"));

#[cfg(feature = "ascon")]
mod ascon {
    use crate::duplex_sponge::Permutation;
    use core::ptr;

    #[derive(Clone, Debug, Default)]
    pub struct Ascon12;

    impl Permutation<40> for Ascon12 {
        type U = u8;

        fn permute(&self, state: &[u8; 40]) -> [u8; 40] {
            let mut words = [0u64; 5];
            unsafe {
                ptr::copy_nonoverlapping(
                    state.as_ptr(),
                    words.as_mut_ptr().cast::<u8>(),
                    state.len(),
                );
            }

            ascon::permute12(&mut words);

            let mut new_state = [0u8; 40];
            unsafe {
                ptr::copy_nonoverlapping(
                    words.as_ptr().cast::<u8>(),
                    new_state.as_mut_ptr(),
                    new_state.len(),
                );
            }
            new_state
        }
    }
}

#[cfg(feature = "keccak")]
mod keccak {
    use core::fmt::Debug;

    use crate::duplex_sponge::Permutation;
    use ::keccak::{Keccak, State1600};

    const STATE_BYTES: usize = 200;
    const WORD_BYTES: usize = 8;
    const _: () = assert!(STATE_BYTES == ::keccak::PLEN * WORD_BYTES);

    /// Keccak permutation internal state: 25 64-bit words,
    /// or equivalently 200 bytes in little-endian order.
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct KeccakF1600;

    impl Permutation<STATE_BYTES> for KeccakF1600 {
        type U = u8;

        fn permute(&self, state: &[u8; STATE_BYTES]) -> [u8; STATE_BYTES] {
            let mut new_state = *state;
            self.permute_mut(&mut new_state);
            new_state
        }

        fn permute_mut(&self, state: &mut [u8; 200]) {
            let mut words = [0u64; 25];
            unsafe {
                ptr::copy_nonoverlapping(
                    state.as_ptr(),
                    words.as_mut_ptr().cast::<u8>(),
                    state.len(),
                );
            }

            f1600(&mut words);

            unsafe {
                ptr::copy_nonoverlapping(
                    words.as_ptr().cast::<u8>(),
                    state.as_mut_ptr(),
                    state.len(),
                );
            }
      }

    fn f1600(state: &mut State1600) {
        Keccak::new().with_f1600(|f1600| f1600(state));
    }
}
