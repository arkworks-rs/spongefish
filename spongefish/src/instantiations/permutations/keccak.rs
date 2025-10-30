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
        unsafe { keccak::f1600(core::mem::transmute(&mut new_state)) };
        new_state
    }
}
