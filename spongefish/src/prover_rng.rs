use rand::{CryptoRng, RngCore};

use crate::{duplex_sponge::DuplexSpongeInterface, keccak::Keccak};

/// A cryptographically-secure random number generator that is bound to the protocol transcript.
///
/// For most public-coin protocols it is *vital* not to have two different verifier messages for the same prover message.
/// For this reason, we construct a Rng that will absorb whatever the verifier absorbs, and that in addition
/// it is seeded by a cryptographic random number generator (by default, [`rand::rngs::OsRng`]).
///
/// Every time a challenge is being generated, the private prover sponge is ratcheted, so that it can't be inverted and the randomness recovered.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProverPrivateRng<R: RngCore + CryptoRng> {
    /// The duplex sponge that is used to generate the random coins.
    ds: Keccak,
    /// The cryptographic random number generator that seeds the sponge.
    csrng: R,
}

impl<R: RngCore + CryptoRng> ProverPrivateRng<R> {
    pub(crate) fn new(domain_separator: [u8; 32], csrng: R) -> Self {
        let mut result = ProverPrivateRng {
            ds: Keccak::default(),
            csrng,
        };
        result.absorb(&domain_separator);
        result
    }

    pub(crate) fn absorb(&mut self, bytes: &[u8]) {
        self.ds.absorb_unchecked(bytes);
    }

    pub(crate) fn ratchet(&mut self) {
        self.ds.ratchet_unchecked();
    }
}

impl<R: RngCore + CryptoRng> RngCore for ProverPrivateRng<R> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(buf.as_mut());
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(buf.as_mut());
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Seed (at most) 32 bytes of randomness from the CSRNG
        let len = usize::min(dest.len(), 32);
        self.csrng.fill_bytes(&mut dest[..len]);
        self.ds.absorb_unchecked(&dest[..len]);
        // fill `dest` with the output of the sponge
        self.ds.squeeze_unchecked(dest);
        // erase the state from the sponge so that it can't be reverted
        self.ds.ratchet_unchecked();
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ProverPrivateRng<R> {}

/// Implements the version of `rand` arkworks usses
#[cfg(feature = "arkworks-algebra")]
impl<R: RngCore + CryptoRng> ark_std::rand::RngCore for ProverPrivateRng<R> {
    fn next_u32(&mut self) -> u32 {
        <Self as RngCore>::next_u32(self)
    }

    fn next_u64(&mut self) -> u64 {
        <Self as RngCore>::next_u64(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        <Self as RngCore>::fill_bytes(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        <Self as RngCore>::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "arkworks-algebra")]
impl<R: RngCore + CryptoRng> ark_std::rand::CryptoRng for ProverPrivateRng<R> {}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn test_prover_state_clone_doesnt_change_rng_output() {
        let mut ppr1 = ProverPrivateRng::new([0; 32], StdRng::from_os_rng());
        let mut ppr2 = ppr1.clone();

        let mut buf1 = [0u8; 4];
        ppr1.fill_bytes(&mut buf1);

        let mut buf2 = [0u8; 4];
        ppr2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_prover_state_ratcheting_changes_rng_output() {
        let mut ppr1 = ProverPrivateRng::new([0; 32], StdRng::from_os_rng());
        let mut ppr2 = ppr1.clone();

        let mut buf1 = [0u8; 4];
        ppr1.fill_bytes(&mut buf1);

        ppr2.ratchet();

        let mut buf2 = [0u8; 4];
        ppr2.fill_bytes(&mut buf2);

        assert_ne!(buf1, buf2);
    }
}
