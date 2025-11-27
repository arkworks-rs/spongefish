use crate::{Permutation, Unit};

pub type BabyBear = risc0_zkp::field::baby_bear::BabyBearElem;

#[derive(Clone, Debug)]
struct RiscZeroBabyBearPoseidon2_24 { }

impl Unit for BabyBear {
    const ZERO: Self = BabyBear::new(0);
}


impl Permutation<24> for RiscZeroBabyBearPoseidon2_24 {
    type U = BabyBear;

    fn permute(&self, state: &[Self::U; 24]) -> [Self::U; 24] {
        let mut new_state = *state;
        risc0_zkp::core::hash::poseidon2::poseidon2_mix(&mut new_state);
        new_state
    }

    fn permute_mut(&self, state: &mut [Self::U; 24]) {
        risc0_zkp::core::hash::poseidon2::poseidon2_mix(state);
    }
}
