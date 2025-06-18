use crate::{pattern::Label, Unit};

pub trait Pattern {
    type Unit: Unit;

    fn ratchet(&mut self);
    fn public_unit(&mut self, label: Label);
    fn public_units(&mut self, label: Label, size: usize);
    fn message_unit(&mut self, label: Label);
    fn message_units(&mut self, label: Label, size: usize);
    fn challenge_unit(&mut self, label: Label);
    fn challenge_units(&mut self, label: Label, size: usize);
    fn hint_bytes(&mut self, label: Label, size: usize);
    fn hint_bytes_dynamic(&mut self, label: Label);
}
