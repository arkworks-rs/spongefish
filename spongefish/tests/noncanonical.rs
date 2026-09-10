//! A NARG string shouldn't be malleable.
//!
//! If a prover can maul a message into a second byte string that parses to the same value,
//! we lose a soundness property called simulation extractability (as well as universal composability).
//! This file provides one such exmaple that **should NOT** be reproduced.
use spongefish::{
    Argument, ByteArray, Decoding, Encoding, Narg, NargDeserialize, NargReader, Transcript,
    VerificationError, Witness,
};

/// A prime small enough that `a` and `a + P` both fit in `u64`.
const P: u64 = (1 << 61) - 1;

/// The hazardous codec: `deserialize` reduces mod `P` instead of rejecting a
/// non-canonical encoding, so `encode(deserialize(b))` is not `b`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Elem(u64);

impl Encoding for Elem {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.to_le_bytes()
    }
}

impl NargDeserialize for Elem {
    type Error = VerificationError;

    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> Result<Self, Self::Error> {
        // The bug, stated plainly. A canonical codec would reject `v >= P`.
        let bytes = reader.take_array::<8>().ok_or(VerificationError)?;
        Ok(Self(u64::from_le_bytes(bytes) % P))
    }
}

impl Decoding for Elem {
    type Repr = ByteArray<8>;
    fn decode(buf: ByteArray<8>) -> Self {
        Self(u64::from_le_bytes(*buf.as_ref()) % P)
    }
}

struct Claim(Elem);

impl Encoding for Claim {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0 .0.to_le_bytes()
    }
}

struct Toy;

impl Argument for Toy {
    type Instance = Claim;
    type Witness = Elem;
    type Output = ();

    fn run<T: Transcript>(
        transcript: &mut T,
        instance: &Claim,
        witness: Witness<&Elem>,
    ) -> Result<(), VerificationError> {
        let a = transcript.prover_message(witness.map(|w| *w))?;
        let c: Elem = transcript.verifier_message();
        let z = transcript.prover_message(Witness::known(Elem((a.0 + c.0) % P)))?;
        transcript.check(|| z.0 == (a.0 + c.0) % P)?;
        transcript.check(|| a.0 == instance.0 .0)
    }
}

#[test]
fn a_second_encoding_of_the_same_message_is_rejected() {
    let sid = Narg::derive_session_id(b"noncanonical-witness");
    let w = Elem(5);
    let instance = Claim(w);

    let (narg, ()) = Narg::prove_with_session_id::<Toy>(&sid, &instance, &w).expect("prover");
    assert!(
        Narg::verify_with_session_id::<Toy>(&sid, &instance, &narg).is_ok(),
        "honest proof must verify"
    );

    // Rewrite the first message as `a + P`: a different byte string that the
    // deserializer maps to the same field element.
    let mut mauled = narg.clone();
    let a = u64::from_le_bytes(mauled[..8].try_into().unwrap());
    mauled[..8].copy_from_slice(&(a + P).to_le_bytes());
    assert_ne!(mauled, narg, "the maul must actually change the bytes");

    assert!(
        Narg::verify_with_session_id::<Toy>(&sid, &instance, &mauled).is_err(),
        "a second accepting NARG string exists for one statement: the verifier absorbed a \
         re-encoding of what it parsed instead of the bytes it read"
    );
}
