use risc0_zkp::field::baby_bear::BabyBearElem;
use spongefish::Permutation;

#[derive(Clone, Debug, Default)]
pub struct RiscZeroBabyBearPoseidon2_24;

impl Permutation<24> for RiscZeroBabyBearPoseidon2_24 {
    type U = BabyBearElem;

    fn permute(&self, state: &[Self::U; 24]) -> [Self::U; 24] {
        let mut new_state = *state;
        risc0_zkp::core::hash::poseidon2::poseidon2_mix(&mut new_state);
        new_state
    }

    fn permute_mut(&self, state: &mut [Self::U; 24]) {
        risc0_zkp::core::hash::poseidon2::poseidon2_mix(state);
    }
}
