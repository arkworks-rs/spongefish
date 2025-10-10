use group::{ff::PrimeField, Group, GroupEncoding};

use super::{FieldDomainSeparator, GroupDomainSeparator};
use crate::{
    codecs::{bytes_modp, bytes_uniform_modp},
    ByteDomainSeparator, DomainSeparator, DuplexSpongeInterface,
};

impl<F, H> FieldDomainSeparator<F> for DomainSeparator<H>
where
    F: PrimeField,
    H: DuplexSpongeInterface,
{
    fn add_scalars(self, count: usize, label: &str) -> Self {
        self.add_bytes(count * bytes_modp(F::NUM_BITS), label)
    }

    fn challenge_scalars(self, count: usize, label: &str) -> Self {
        self.challenge_bytes(count * bytes_uniform_modp(F::NUM_BITS), label)
    }
}

impl<G, H> GroupDomainSeparator<G> for DomainSeparator<H>
where
    G: Group + GroupEncoding,
    G::Repr: AsRef<[u8]>,
    H: DuplexSpongeInterface,
{
    fn add_points(self, count: usize, label: &str) -> Self {
        let n = G::Repr::default().as_ref().len();
        self.add_bytes(count * n, label)
    }
}
