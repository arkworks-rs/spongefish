#[cfg(feature = "ascon")]
pub use ascon::Ascon12;
#[cfg(feature = "keccak")]
pub use keccak::KeccakF1600;

#[cfg(feature = "ascon")]
mod ascon {

    #[derive(Clone, Debug, Default)]
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

        fn permute_mut(&self, state: &mut [u8; STATE_BYTES]) {
            let mut words = bytes_to_words(state);
            f1600(&mut words);
            words_to_bytes(&words, state);
        }
    }

    fn f1600(state: &mut State1600) {
        Keccak::new().with_f1600(|f1600| f1600(state));
    }

    fn bytes_to_words(state: &[u8; STATE_BYTES]) -> State1600 {
        core::array::from_fn(|i| {
            let start = i * WORD_BYTES;
            let mut word = [0; WORD_BYTES];
            word.copy_from_slice(&state[start..start + WORD_BYTES]);
            u64::from_le_bytes(word)
        })
    }

    fn words_to_bytes(words: &State1600, state: &mut [u8; STATE_BYTES]) {
        for (chunk, word) in state.chunks_exact_mut(WORD_BYTES).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
    }
}
