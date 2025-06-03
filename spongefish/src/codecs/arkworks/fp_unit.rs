//! Implementations tu use an arkworks prime field [`Fp`] as a unit in the transcript.
use std::{
    borrow::Cow,
    io::{self, ErrorKind},
};

use ark_ff::{AdditiveGroup, BigInt, Fp, FpConfig, PrimeField as _};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use zerocopy::IntoBytes as _;

use crate::{codecs::bytes, ReadError, Unit};

/// Implement the [`Unit`] trait for all arkworks prime fields [`Fp`].
impl<C: FpConfig<N>, const N: usize> Unit for Fp<C, N> {
    fn write(bunch: &[Self], mut w: impl io::Write) {
        // Loop over the bunch to avoid the length prefix that
        // comes from serializing &[Self] directly.
        for item in bunch {
            item.serialize_compressed(&mut w)
                .expect("Writer is infallible");
        }
    }

    fn read(mut bytes: &[u8], bunch: &mut [Self]) -> Result<usize, ReadError> {
        let old_len = bytes.len();
        for item in bunch {
            *item = Self::deserialize_compressed(&mut bytes).map_err(|e| match e {
                SerializationError::IoError(io_err) => match io_err.kind() {
                    ErrorKind::UnexpectedEof => ReadError::UnexpectEndOfTranscript,
                    _ => ReadError::IvalidData,
                },
                SerializationError::NotEnoughSpace => ReadError::UnexpectEndOfTranscript,
                _ => ReadError::IvalidData,
            })?;
        }
        Ok(old_len - bytes.len())
    }
}

/// Implement the [`bytes::UnitBytes`] trait for all arkworks prime fields [`Fp`].
impl<C, const N: usize> bytes::UnitBytes for Fp<C, N>
where
    C: FpConfig<N>,
{
    fn pack_units_required(bytes: usize) -> usize {
        bytes.div_ceil(pack_bytes::<C, N>())
    }

    fn random_units_required(bytes: usize) -> usize {
        bytes.div_ceil(random_bytes_in_random_modp::<N>(C::MODULUS))
    }

    fn pack_bytes(bytes: &[u8]) -> Cow<[Self]> {
        let mut out = vec![Self::ZERO; Self::pack_units_required(bytes.len())];
        for (chunk, out) in bytes.chunks(pack_bytes::<C, N>()).zip(out.iter_mut()) {
            let mut limbs = [0_u64; N];
            limbs.as_mut_bytes()[..chunk.len()].copy_from_slice(chunk);
            *out = Self::from_bigint(BigInt(limbs))
                .expect("packing can not produce unreduced elements");
        }
        Cow::Owned(out)
    }

    fn unpack_bytes(units: &[Self], out: &mut [u8]) {
        assert_eq!(units.len(), Self::pack_units_required(out.len()));
        for (unit, chunk) in units.iter().zip(out.chunks_mut(pack_bytes::<C, N>())) {
            let limbs = unit.into_bigint().0;
            chunk.copy_from_slice(&limbs.as_bytes()[..chunk.len()]);
        }
    }

    fn random_bytes(units: &[Self], out: &mut [u8]) {
        assert_eq!(units.len(), Self::random_units_required(out.len()));
        let bytes_per_element = random_bytes_in_random_modp(C::MODULUS);
        for (unit, chunk) in units.iter().zip(out.chunks_mut(bytes_per_element)) {
            let limbs = unit.into_bigint().0;
            chunk.copy_from_slice(&limbs.as_bytes()[..chunk.len()]);
        }
    }
}

/// Number of bytes that can unambiguously be packed into a field element.
const fn pack_bytes<C: FpConfig<N>, const N: usize>() -> usize {
    let safe_bits = C::MODULUS.const_num_bits() - 1;
    assert!(safe_bits >= 8, "Can not safely pack bytes into this field.");
    (safe_bits / 8) as usize
}

/// Number of uniformly random bytes of in a uniformly-distributed element in `[0, b)`.
///
/// This function returns the maximum n for which
/// `Uniform([b]) mod 2^n`
/// and
/// `Uniform([2^n])`
/// are statistically indistinguishable.
/// Given \(b = q 2^n + r\) the statistical distance
/// is \(\frac{2r}{ab}(a-r)\).
// TODO: For small fields this will always return zero. Instead we should combine multiple elements
// to get enough combined entropy. For this we need to find k such that p^k > 2^{8*k + 128} and then
// compute sum_i f_i * p^i mod 2^{8*k} to get random bytes.
fn random_bits_in_random_modp<const N: usize>(b: BigInt<N>) -> usize {
    use ark_ff::{BigInt, BigInteger};
    // XXX. is it correct to have num_bits+1 here?
    for n in (0..=b.num_bits()).rev() {
        // compute the remainder of b by 2^n
        let r_bits = &b.to_bits_le()[..n as usize];
        let r = BigInt::<N>::from_bits_le(r_bits);
        let log2_a_minus_r = r_bits.iter().rev().skip_while(|&&bit| bit).count() as u32;
        if b.num_bits() + n - 1 - r.num_bits() - log2_a_minus_r >= 128 {
            return n as usize;
        }
    }
    0
}

/// Same as above, but for bytes
fn random_bytes_in_random_modp<const N: usize>(modulus: BigInt<N>) -> usize {
    random_bits_in_random_modp(modulus) / 8
}
