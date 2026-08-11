//! A NARG string must have exactly one accepting form.
//!
//! The verifier can absorb a message two ways: the bytes it actually read, or
//! a re-encoding of the value it parsed out of them. Those agree only when
//! deserialization is canonical — and a deserializer that *reduces* rather than
//! *rejects* is an easy thing to write. The crate's own crate-level example
//! used to have one.
//!
//! Under re-encoding, a prover can maul a message into a second byte string
//! that parses to the same value: the sponge sees the canonical form either
//! way, derives the same challenge, and accepts both. That is malleability
//! inside a message rather than after it, so `check_eof` does not see it and
//! neither does a bit-flip sweep — every flip that survives parsing lands on a
//! different value, not on a different encoding of the same one.

use spongefish::{Argument, Narg, Transcript, Witness};
use spongefish::{
    ByteArray, Decoding, Encoding, NargDeserialize, NargReader, StdHash, VerificationResult,
};

/// A prime small enough that `a` and `a + P` both fit in `u64`.
const P: u64 = (1 << 61) - 1;

/// The hazardous codec: `deserialize` reduces mod `P` instead of rejecting a
/// non-canonical encoding, so `encode(deserialize(b))` is not `b`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Elem(u64);

impl Encoding<[u8]> for Elem {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.to_le_bytes()
    }
}

impl NargDeserialize for Elem {
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> VerificationResult<Self> {
        // The bug, stated plainly. A canonical codec would reject `v >= P`.
        Ok(Self(u64::from_le_bytes(reader.take_array::<8>()?) % P))
    }
}

impl Decoding<[u8]> for Elem {
    type Repr = ByteArray<8>;
    fn decode(buf: ByteArray<8>) -> Self {
        Self(u64::from_le_bytes(*buf.as_ref()) % P)
    }
}

struct Claim(Elem);

impl Encoding<[u8]> for Claim {
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
    ) -> VerificationResult<()> {
        let a = transcript.prover_message(witness.map(|w| *w))?;
        let c: Elem = transcript.verifier_message();
        let z = transcript.prover_message(Witness::known(Elem((a.0 + c.0) % P)))?;
        transcript.check(|| z.0 == (a.0 + c.0) % P)?;
        transcript.check(|| a.0 == instance.0 .0)
    }
}

#[test]
fn a_second_encoding_of_the_same_message_is_rejected() {
    let sid = spongefish::derive_session_id::<StdHash>(b"noncanonical-witness");
    let w = Elem(5);
    let instance = Claim(w);

    let (narg, ()) = Narg::prove::<Toy>(&sid, &instance, &w).expect("prover");
    assert!(
        Narg::verify::<Toy>(&sid, &instance, &narg).is_ok(),
        "honest proof must verify"
    );

    // Rewrite the first message as `a + P`: a different byte string that the
    // deserializer maps to the same field element.
    let mut mauled = narg.clone();
    let a = u64::from_le_bytes(mauled[..8].try_into().unwrap());
    mauled[..8].copy_from_slice(&(a + P).to_le_bytes());
    assert_ne!(mauled, narg, "the maul must actually change the bytes");

    assert!(
        Narg::verify::<Toy>(&sid, &instance, &mauled).is_err(),
        "a second accepting NARG string exists for one statement: the verifier absorbed a \
         re-encoding of what it parsed instead of the bytes it read"
    );
}
