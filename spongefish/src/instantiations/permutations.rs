#[cfg(feature = "ascon")]
pub use ascon::Ascon12;
#[cfg(feature = "keccak")]
pub use keccak::KeccakF1600;

#[cfg(feature = "ascon")]
mod ascon {
    use crate::duplex_sponge::Permutation;

    const STATE_BYTES: usize = 40;
    const WORD_BYTES: usize = 8;
    const _: () = assert!(STATE_BYTES == core::mem::size_of::<ascon::State>());

    /// Ascon permutation internal state: 5 64-bit words,
    /// or equivalently 40 bytes in little-endian order.
    #[derive(Clone, Debug, Default)]
    pub struct Ascon12;

    impl Permutation<STATE_BYTES> for Ascon12 {
        type U = u8;

        fn permute(&self, state: &[u8; STATE_BYTES]) -> [u8; STATE_BYTES] {
            let mut new_state = *state;
            self.permute_mut(&mut new_state);
            new_state
        }

        fn permute_mut(&self, state: &mut [u8; STATE_BYTES]) {
            let mut words = bytes_to_words(state);
            ascon::permute12(&mut words);
            words_to_bytes(&words, state);
        }
    }

    fn bytes_to_words(state: &[u8; STATE_BYTES]) -> ascon::State {
        core::array::from_fn(|i| {
            let start = i * WORD_BYTES;
            let mut word = [0; WORD_BYTES];
            word.copy_from_slice(&state[start..start + WORD_BYTES]);
            u64::from_le_bytes(word)
        })
    }

    fn words_to_bytes(words: &ascon::State, state: &mut [u8; STATE_BYTES]) {
        for (chunk, word) in state.as_chunks_mut::<WORD_BYTES>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Serialize words in little-endian order, independently of the
        /// conversion functions under test.
        fn serialize_le(words: &ascon::State) -> [u8; STATE_BYTES] {
            let mut bytes = [0u8; STATE_BYTES];
            for (chunk, word) in bytes.chunks_exact_mut(WORD_BYTES).zip(words) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            bytes
        }

        /// Known-answer test for the permutation, using the word-level vectors
        /// from the `ascon` crate's own test suite. Serializing the words with
        /// an explicit byte order pins the state layout to little-endian
        /// independently of the target's native endianness.
        #[test]
        fn ascon12_little_endian_known_answer() {
            let input_words: ascon::State = [
                0x0123_4567_89ab_cdef,
                0xef01_2345_6789_abcd,
                0xcdef_0123_4567_89ab,
                0xabcd_ef01_2345_6789,
                0x89ab_cdef_0123_4567,
            ];
            let output_words: ascon::State = [
                0x2064_16df_c624_bb14,
                0x1b0c_47a6_0105_8aab,
                0x8934_cfc9_3814_cddd,
                0xa973_8d28_7a74_8e4b,
                0xddd9_34f0_58af_c7e1,
            ];

            let input = serialize_le(&input_words);
            let expected = serialize_le(&output_words);

            assert_eq!(Ascon12.permute(&input), expected);
        }
    }
}

#[cfg(feature = "keccak")]
mod keccak {
    use core::fmt::Debug;

    use ::keccak::{Keccak, State1600};

    use crate::duplex_sponge::Permutation;

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
        for (chunk, word) in state.as_chunks_mut::<WORD_BYTES>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
    }
}
