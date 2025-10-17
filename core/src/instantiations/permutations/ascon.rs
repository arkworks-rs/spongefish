use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::duplex_sponge::Permutation;

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Ascon12([u8; 40]);

impl Permutation for Ascon12 {
    const N: usize = 16 + 24;
    const R: usize = 16;
    type U = u8;

    fn new() -> Self {
        Self([0; size_of::<u64>() * 5])
    }

    fn permute(&mut self) {
        let mut state = ascon::State::from(&self.0);
        state.permute_12();
        self.0.copy_from_slice(&state.as_bytes());
    }
}

impl AsMut<[u8]> for Ascon12 {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl AsRef<[u8]> for Ascon12 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
