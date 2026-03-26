use crate::Unit;

pub type BabyBear = risc0_zkp::field::baby_bear::BabyBearElem;

impl Unit for BabyBear {
    const ZERO: Self = Self::new(0);
}
