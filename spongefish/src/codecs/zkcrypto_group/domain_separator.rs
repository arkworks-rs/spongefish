use group::{ff::PrimeField, Group, GroupEncoding};

use super::{FieldPattern, GroupPattern};
use crate::{
    codecs::{bytes, bytes_modp, bytes_uniform_modp},
    pattern::{self, Label, Length},
};

impl<P, F> FieldPattern<F> for P
where
    P: pattern::Pattern + bytes::Pattern,
    F: PrimeField,
{
    fn add_scalars(&mut self, label: Label, count: usize) {
        self.begin_message::<F>(label, Length::Fixed(count));
        self.message_bytes("bytes", count * bytes_modp(F::NUM_BITS));
        self.end_message::<F>(label, Length::Fixed(count));
    }

    fn challenge_scalars(&mut self, label: Label, count: usize) {
        self.begin_challenge::<F>(label, Length::Fixed(count));
        self.challenge_bytes("bytes", count * bytes_uniform_modp(F::NUM_BITS));
        self.end_challenge::<F>(label, Length::Fixed(count));
    }
}

impl<P, G> GroupPattern<G> for P
where
    P: pattern::Pattern + bytes::Pattern,
    G: Group + GroupEncoding,
    G::Repr: AsRef<[u8]>,
{
    fn add_points(&mut self, label: Label, count: usize) {
        self.begin_message::<G>(label, Length::Fixed(count));
        let n = G::Repr::default().as_ref().len();
        self.message_bytes("bytes", count * n);
        self.end_message::<G>(label, Length::Fixed(count));
    }
}
