use crate::duplex_sponge::Permutation;

#[derive(Clone, Debug)]
pub struct Ascon12;

impl Permutation<40> for Ascon12 {
    type U = u8;

    fn permute(&self, state: &[u8; 40]) -> [u8; 40] {
        ascon::State::from(state).as_bytes()
    }
}
