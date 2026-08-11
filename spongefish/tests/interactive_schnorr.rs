//! Schnorr exercises the complete `Argument` flow: private sampling, prover
//! and verifier messages, witness arithmetic, and the verification equation.

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use spongefish::{Argument, Narg, Transcript, Witness};
use spongefish::{
    ByteArray, Decoding, Encoding, NargDeserialize, NargReader, StdHash, VerificationError,
    VerificationResult,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Point(RistrettoPoint);
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fr(Scalar);

impl Point {
    fn generator() -> Self {
        Self(RistrettoPoint::mul_base(&Scalar::from(1u64)))
    }
    fn mul(self, s: Fr) -> Self {
        Self(self.0 * s.0)
    }
    fn add(self, o: Self) -> Self {
        Self(self.0 + o.0)
    }
}

impl Fr {
    fn add(self, o: Self) -> Self {
        Self(self.0 + o.0)
    }
    fn mul(self, o: Self) -> Self {
        Self(self.0 * o.0)
    }
}

impl Encoding<[u8]> for Point {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.compress().to_bytes()
    }
}
impl NargDeserialize for Point {
    fn deserialize_from_narg(r: &mut NargReader<'_>) -> VerificationResult<Self> {
        CompressedRistretto(r.take_array::<32>()?)
            .decompress()
            .map(Point)
            .ok_or(VerificationError)
    }
}
impl Decoding<[u8]> for Point {
    type Repr = ByteArray<64>;
    fn decode(b: ByteArray<64>) -> Self {
        Self(RistrettoPoint::from_uniform_bytes(b.as_ref()))
    }
}

impl Encoding<[u8]> for Fr {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.to_bytes()
    }
}
impl NargDeserialize for Fr {
    fn deserialize_from_narg(r: &mut NargReader<'_>) -> VerificationResult<Self> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(r.take_array::<32>()?))
            .map(Fr)
            .ok_or(VerificationError)
    }
}
impl Decoding<[u8]> for Fr {
    type Repr = ByteArray<64>;
    fn decode(b: ByteArray<64>) -> Self {
        Self(Scalar::from_bytes_mod_order_wide(b.as_ref()))
    }
}

pub struct Dlog {
    g: Point,
    pk: Point,
}

impl Encoding<[u8]> for Dlog {
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.g.encode().as_ref());
        out[32..].copy_from_slice(self.pk.encode().as_ref());
        out
    }
}

// ===========================================================================

struct Schnorr;

impl Argument for Schnorr {
    type Instance = Dlog;
    type Witness = Fr;
    type Output = ();

    fn run<T: Transcript>(
        transcript: &mut T,
        instance: &Dlog,
        witness: Witness<&Fr>,
    ) -> VerificationResult<()> {
        let k = transcript.sample::<Fr>();
        let a = transcript.prover_message(k.map(|k| instance.g.mul(k)))?;
        let c: Fr = transcript.verifier_message();
        let z = transcript.prover_message(k.zip(witness).map(|(k, x)| k.add(c.mul(*x))))?;
        transcript.check(|| instance.g.mul(z) == a.add(instance.pk.mul(c)))
    }
}

// ===========================================================================

fn setup() -> (spongefish::SessionId, Dlog, Fr) {
    let g = Point::generator();
    let x = Fr(Scalar::from(31337u64));
    (
        spongefish::derive_session_id::<StdHash>(b"https://example.com/typed/v1 schnorr"),
        Dlog { g, pk: g.mul(x) },
        x,
    )
}

#[test]
fn correctness() {
    let (sid, instance, x) = setup();
    let (narg, ()) = Narg::prove::<Schnorr>(&sid, &instance, &x).expect("prover");
    assert_eq!(narg.len(), 64);
    assert!(Narg::verify::<Schnorr>(&sid, &instance, &narg).is_ok());
}

#[test]
fn nonces_are_not_reused() {
    let (sid, instance, x) = setup();
    let (a, ()) = Narg::prove::<Schnorr>(&sid, &instance, &x).unwrap();
    let (b, ()) = Narg::prove::<Schnorr>(&sid, &instance, &x).unwrap();
    assert_ne!(a, b);
}

/// `check` takes a closure so the prover can decline to evaluate it. Confirm
/// that it actually does: in a release build the verification equation is never
/// computed on the prover, which for a sigma protocol is the two scalar
/// multiplications that dominate verification.
///
/// The counter is a `static` rather than a field, because an
/// `Argument` may not carry data — a field on it would reach neither
/// the sponge nor the session identifier.
#[test]
fn the_prover_does_not_compute_the_verification_equation_in_release() {
    use core::sync::atomic::{AtomicU32, Ordering};

    static EVALUATIONS: AtomicU32 = AtomicU32::new(0);

    struct Counted;

    impl Argument for Counted {
        type Instance = Dlog;
        type Witness = Fr;
        type Output = ();

        fn run<T: Transcript>(
            transcript: &mut T,
            _instance: &Dlog,
            _witness: Witness<&Fr>,
        ) -> VerificationResult<()> {
            transcript.check(|| {
                EVALUATIONS.fetch_add(1, Ordering::Relaxed);
                true
            })
        }
    }

    let (sid, instance, x) = setup();
    let (narg, ()) = Narg::prove::<Counted>(&sid, &instance, &x).expect("prover");

    // Debug builds keep it as a completeness self-test; release builds skip it.
    let expected = u32::from(cfg!(debug_assertions));
    assert_eq!(
        EVALUATIONS.swap(0, Ordering::Relaxed),
        expected,
        "prover-side evaluations"
    );

    // The verifier always evaluates it, whatever the profile.
    assert!(Narg::verify::<Counted>(&sid, &instance, &narg).is_ok());
    assert_eq!(
        EVALUATIONS.load(Ordering::Relaxed),
        1,
        "the verifier must always check"
    );
}
