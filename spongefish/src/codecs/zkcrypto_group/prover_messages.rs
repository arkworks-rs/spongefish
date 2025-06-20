use group::{ff::PrimeField, Group, GroupEncoding};
use rand::{CryptoRng, RngCore};

use super::{CommonFieldToUnit, CommonGroupToUnit, FieldToUnitSerialize, GroupToUnitSerialize};
use crate::{BytesToUnitSerialize, CommonUnitToBytes, DuplexSpongeInterface, ProverState};

impl<F, H, R> FieldToUnitSerialize<F> for ProverState<H, u8, R>
where
    F: PrimeField,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn add_scalars(&mut self, input: &[F]) {
        let mut buf = Vec::new();
        input.iter().for_each(|i| buf.extend(i.to_repr().as_ref()));
        self.add_bytes(&buf);
    }
}

impl<G, H, R> CommonGroupToUnit<G> for ProverState<H, u8, R>
where
    G: Group + GroupEncoding,
    G::Repr: AsRef<[u8]>,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    type Repr = Vec<u8>;
    fn public_points(&mut self, input: &[G]) -> Self::Repr {
        let mut buf = Vec::new();
        for p in input {
            buf.extend_from_slice(<G as GroupEncoding>::to_bytes(p).as_ref());
        }
        self.public_bytes(&buf);
        buf
    }
}

impl<G, H, R> GroupToUnitSerialize<G> for ProverState<H, u8, R>
where
    G: Group + GroupEncoding,
    G::Repr: AsRef<[u8]>,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn add_points(&mut self, input: &[G]) {
        let mut buf = Vec::new();
        for p in input {
            buf.extend_from_slice(<G as GroupEncoding>::to_bytes(p).as_ref());
        }
        self.add_bytes(&buf);
    }
}

impl<F, T> CommonFieldToUnit<F> for T
where
    F: PrimeField,
    T: CommonUnitToBytes,
{
    type Repr = Vec<u8>;

    fn public_scalars(&mut self, input: &[F]) -> Self::Repr {
        let mut buf = Vec::new();
        input.iter().for_each(|i| buf.extend(i.to_repr().as_ref()));
        self.public_bytes(&buf);
        buf
    }
}
