use crate::Unit;

pub type BabyBear = risc0_zkp::field::baby_bear::BabyBearElem;

impl Unit for BabyBear {
    const ZERO: Self = BabyBear::new(0);
}
