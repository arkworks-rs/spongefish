//! Example: a Schnorr proof of knowledge of a discrete logarithm over
//! ristretto255, using the one-off closure codecs.
//!
//! `RistrettoPoint` and `Scalar` are foreign types, so the orphan rule rules
//! out implementing [`Encoding`][spongefish::Encoding] /
//! [`Decoding`][spongefish::Decoding] for them. The closure codecs are the
//! escape hatch; gathering them into an extension trait per state keeps every
//! codec in one place and lets the protocol itself read in the language of the
//! group.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use spongefish::{PrivateRng, ProverState, VerificationError, VerificationResult, VerifierState};

/// The application tag: prover and verifier derive the session identifier from
/// it, and any change to the codecs below must change it too.
const TAG: &[u8] = b"spongefish examples/schnorr proof";

/// Bytes per uniform scalar: 32 bytes of scalar oversampled by 128 bits to
/// bound the reduction bias (`DecodeUint` of draft-irtf-cfrg-fiat-shamir).
const WIDE_LEN: usize = 64;

/// Reduces `WIDE_LEN` uniform bytes into a uniform scalar. Prover and verifier
/// derive the challenge through this one function, so they cannot drift apart.
///
/// # Panics
///
/// Panics unless `bytes` is exactly `WIDE_LEN` long.
fn wide_scalar(bytes: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(bytes.try_into().expect("WIDE_LEN bytes"))
}

/// Samples a uniform scalar from the prover's private coins.
fn random_scalar(rng: &mut PrivateRng) -> Scalar {
    let mut wide = [0u8; WIDE_LEN];
    rng.fill_bytes(&mut wide);
    wide_scalar(&wide)
}

/// The wire encoding of a group element: its 32-byte compressed form.
fn compress(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

/// Splits a fixed-size chunk off the front of the NARG cursor.
fn take<const N: usize>(buf: &mut &[u8]) -> VerificationResult<[u8; N]> {
    let (head, rest) = buf.split_first_chunk().ok_or(VerificationError)?;
    *buf = rest;
    Ok(*head)
}

/// The statement being proven: the generator and the public key, compressed.
#[allow(non_snake_case)]
fn instance(X: &RistrettoPoint) -> [u8; 64] {
    let mut instance = [0u8; 64];
    instance[..32].copy_from_slice(&compress(&RISTRETTO_BASEPOINT_POINT));
    instance[32..].copy_from_slice(&compress(X));
    instance
}

/// The ristretto255 codecs, as seen by the prover.
trait SchnorrProver {
    /// Sends a group element, encoded as its 32-byte compressed form.
    fn prover_point(&mut self, point: &RistrettoPoint);

    /// Sends a scalar, encoded in canonical little-endian 32-byte form.
    fn prover_scalar(&mut self, scalar: &Scalar);

    /// Squeezes a challenge scalar.
    fn verifier_scalar(&mut self) -> Scalar;
}

impl SchnorrProver for ProverState {
    fn prover_point(&mut self, point: &RistrettoPoint) {
        self.prover_message_as(point, compress);
    }

    fn prover_scalar(&mut self, scalar: &Scalar) {
        self.prover_message_as(scalar, Scalar::to_bytes);
    }

    fn verifier_scalar(&mut self) -> Scalar {
        self.verifier_message_as(WIDE_LEN, wide_scalar)
    }
}

/// The same codecs, read back from the NARG string. Each reader rejects
/// non-canonical encodings, as the deserialization must be injective.
trait SchnorrVerifier {
    /// Reads a group element from its compressed form.
    fn prover_point(&mut self) -> VerificationResult<RistrettoPoint>;

    /// Reads a scalar, rejecting non-canonical representatives.
    fn prover_scalar(&mut self) -> VerificationResult<Scalar>;

    /// Squeezes a challenge scalar; the dual of
    /// [`SchnorrProver::verifier_scalar`].
    fn verifier_scalar(&mut self) -> Scalar;
}

impl SchnorrVerifier for VerifierState<'_> {
    fn prover_point(&mut self) -> VerificationResult<RistrettoPoint> {
        self.prover_message_as(|buf| {
            CompressedRistretto(take(buf)?)
                .decompress()
                .ok_or(VerificationError)
        })
    }

    fn prover_scalar(&mut self) -> VerificationResult<Scalar> {
        self.prover_message_as(|buf| {
            Option::from(Scalar::from_canonical_bytes(take(buf)?)).ok_or(VerificationError)
        })
    }

    fn verifier_scalar(&mut self) -> Scalar {
        self.verifier_message_as(WIDE_LEN, wide_scalar)
    }
}

/// Proves knowledge of `x` such that `x * G = X`.
#[allow(non_snake_case)]
fn prove(X: &RistrettoPoint, x: &Scalar) -> Vec<u8> {
    let mut prover_state = ProverState::from_tag(TAG, &instance(X)[..]);

    let k = random_scalar(prover_state.rng());
    let K = RistrettoPoint::mul_base(&k);

    prover_state.prover_point(&K);
    let c = prover_state.verifier_scalar();
    prover_state.prover_scalar(&(k + c * x));

    prover_state.narg_string().to_vec()
}

#[allow(non_snake_case)]
fn verify(X: &RistrettoPoint, narg_string: &[u8]) -> VerificationResult<()> {
    let mut verifier_state = VerifierState::from_tag(TAG, &instance(X)[..], narg_string);

    let K = verifier_state.prover_point()?;
    let c = verifier_state.verifier_scalar();
    let r = verifier_state.prover_scalar()?;

    if RistrettoPoint::mul_base(&r) != K + X * c {
        return Err(VerificationError);
    }
    verifier_state.check_eof()
}

fn main() {
    let sk = random_scalar(&mut PrivateRng::from_os_entropy());
    let pk = RistrettoPoint::mul_base(&sk);

    let narg_string = prove(&pk, &sk);
    println!("Here's a Schnorr signature:\n{}", hex::encode(&narg_string));

    verify(&pk, &narg_string).expect("verification failed");
}
