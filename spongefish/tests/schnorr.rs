//! An example for Schnorr exercises the complete `Argument` flow: private sampling, prover
//! and verifier messages, witness arithmetic, and the verification equation.

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use spongefish::{
    Argument, ByteArray, Decoding, Encoding, Narg, NargDeserialize, NargReader, Transcript,
    VerificationError, Witness,
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

impl Encoding for Point {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.compress().to_bytes()
    }
}
impl NargDeserialize for Point {
    type Error = VerificationError;

    fn deserialize_from_narg(r: &mut NargReader<'_>) -> Result<Self, Self::Error> {
        CompressedRistretto(r.take_array::<32>().ok_or(VerificationError)?)
            .decompress()
            .map(Point)
            .ok_or(VerificationError)
    }
}
impl Decoding for Point {
    type Repr = ByteArray<64>;
    fn decode(b: ByteArray<64>) -> Self {
        Self(RistrettoPoint::from_uniform_bytes(b.as_ref()))
    }
}

impl Encoding for Fr {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.to_bytes()
    }
}
impl NargDeserialize for Fr {
    type Error = VerificationError;

    fn deserialize_from_narg(r: &mut NargReader<'_>) -> Result<Self, Self::Error> {
        let bytes = r.take_array::<32>().ok_or(VerificationError)?;
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .map(Fr)
            .ok_or(VerificationError)
    }
}
impl Decoding for Fr {
    type Repr = ByteArray<64>;
    fn decode(b: ByteArray<64>) -> Self {
        Self(Scalar::from_bytes_mod_order_wide(b.as_ref()))
    }
}

pub struct Dlog {
    g: Point,
    pk: Point,
}

impl Encoding for Dlog {
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
    ) -> Result<(), VerificationError> {
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
        Narg::derive_session_id(b"https://example.com/typed/v1 schnorr"),
        Dlog { g, pk: g.mul(x) },
        x,
    )
}

#[test]
fn correctness() {
    let (sid, instance, x) = setup();
    let (narg, ()) = Narg::prove_with_session_id::<Schnorr>(&sid, &instance, &x).expect("prover");
    assert_eq!(narg.len(), 64);
    assert!(Narg::verify_with_session_id::<Schnorr>(&sid, &instance, &narg).is_ok());
}

#[test]
fn nonces_are_not_reused() {
    let (sid, instance, x) = setup();
    let (a, ()) = Narg::prove_with_session_id::<Schnorr>(&sid, &instance, &x).unwrap();
    let (b, ()) = Narg::prove_with_session_id::<Schnorr>(&sid, &instance, &x).unwrap();
    assert_ne!(a, b);
}
