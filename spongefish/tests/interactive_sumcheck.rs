//! The draft's degree-1 sumcheck, written with `Witness<T>` instead of a macro,
//! checked byte-for-byte against the official CFRG vectors.
//!
//! This is the honest test of the approach. Sumcheck has an instance-driven
//! round count, a witness table folded in place across rounds, and a terminal
//! value both parties compute — everything that makes the erasure question
//! non-trivial. If `Witness<T>` handles this, it handles the design.

use spongefish::{Argument, Narg, Transcript, Witness};
use spongefish::{
    ByteArray, Decoding, Encoding, NargDeserialize, NargReader, StdHash, VerificationError,
    VerificationResult,
};

const P: u32 = (1 << 31) - 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct M31(u32);

impl M31 {
    fn add(self, o: Self) -> Self {
        Self(((u64::from(self.0) + u64::from(o.0)) % u64::from(P)) as u32)
    }
    fn sub(self, o: Self) -> Self {
        Self(((u64::from(self.0) + u64::from(P) - u64::from(o.0)) % u64::from(P)) as u32)
    }
    fn mul(self, o: Self) -> Self {
        Self(((u64::from(self.0) * u64::from(o.0)) % u64::from(P)) as u32)
    }
}

impl Encoding<[u8]> for M31 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.to_le_bytes()
    }
}

impl NargDeserialize for M31 {
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> VerificationResult<Self> {
        let v = u32::from_le_bytes(reader.take_array::<4>()?);
        if v >= P {
            return Err(VerificationError);
        }
        Ok(Self(v))
    }
}

impl Decoding<[u8]> for M31 {
    type Repr = ByteArray<4>;
    fn decode(buf: ByteArray<4>) -> Self {
        Self(u32::from_le_bytes(*buf.as_ref()) % P)
    }
}

pub struct Claim {
    num_variables: u32,
    claimed_sum: M31,
}

impl Encoding<[u8]> for Claim {
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.num_variables.to_le_bytes());
        out[4..].copy_from_slice(self.claimed_sum.encode().as_ref());
        out
    }
}

fn round_coefficients(table: &[M31]) -> (M31, M31) {
    let mut even = M31::default();
    let mut odd = M31::default();
    for pair in table.chunks_exact(2) {
        even = even.add(pair[0]);
        odd = odd.add(pair[1]);
    }
    (even, odd.sub(even))
}

fn fold(table: &[M31], r: M31) -> Vec<M31> {
    table
        .chunks_exact(2)
        .map(|p| p[0].add(r.mul(p[1].sub(p[0]))))
        .collect()
}

// ===========================================================================
// The protocol. One body; `prove` and `verify` instantiate it.
// ===========================================================================

struct Sumcheck;

impl Argument for Sumcheck {
    type Instance = Claim;
    type Witness = Vec<M31>;
    type Output = M31;

    fn run<T: Transcript>(
        transcript: &mut T,
        instance: &Claim,
        witness: Witness<&Vec<M31>>,
    ) -> VerificationResult<M31> {
        // The verifier's `table` is unknown and stays unknown; every `map`
        // below is a no-op on its side.
        let mut table: Witness<Vec<M31>> = witness.map(Clone::clone);
        let mut claim = instance.claimed_sum;

        // Instance-driven, so it is a plain `u32`. A witness-driven bound would
        // be `Witness<u32>`, which is not `IntoIterator` — the macro version needs
        // an analysis and a diagnostic to reject what is simply unwritable here.
        for _ in 0..instance.num_variables {
            let coefficients = table.as_ref().map(|t| round_coefficients(t));
            let a0 = transcript.prover_message(coefficients.map(|c| c.0))?;
            let a1 = transcript.prover_message(coefficients.map(|c| c.1))?;

            // `a0` and `a1` are plain `M31`: sending declassified them. So this
            // is a `bool`, and `check` accepts it.
            transcript.check(|| a0.add(a0).add(a1) == claim)?;

            let r: M31 = transcript.verifier_message();
            claim = a0.add(a1.mul(r));

            table = table.map(|t| fold(&t, r));
        }

        Ok(claim)
    }
}

// ===========================================================================
// Composition. A sub-protocol is just another `Argument` whose `run` you call
// with the same transcript — there is no `call!`, and nothing to teach the
// library about nesting.
// ===========================================================================

struct SumcheckRound;

impl Argument for SumcheckRound {
    type Instance = M31;
    type Witness = Vec<M31>;
    /// The folded claim, and the table after folding — the caller threads both.
    type Output = (M31, Witness<Vec<M31>>);

    fn run<T: Transcript>(
        transcript: &mut T,
        claim: &M31,
        table: Witness<&Vec<M31>>,
    ) -> VerificationResult<(M31, Witness<Vec<M31>>)> {
        let coefficients = table.map(|t| round_coefficients(t));
        let a0 = transcript.prover_message(coefficients.map(|c| c.0))?;
        let a1 = transcript.prover_message(coefficients.map(|c| c.1))?;
        transcript.check(|| a0.add(a0).add(a1) == *claim)?;
        let r: M31 = transcript.verifier_message();
        Ok((a0.add(a1.mul(r)), table.map(|t| fold(t, r))))
    }
}

struct NestedSumcheck;

impl Argument for NestedSumcheck {
    type Instance = Claim;
    type Witness = Vec<M31>;
    type Output = M31;

    fn run<T: Transcript>(
        transcript: &mut T,
        instance: &Claim,
        witness: Witness<&Vec<M31>>,
    ) -> VerificationResult<M31> {
        let mut table = witness.map(Clone::clone);
        let mut claim = instance.claimed_sum;
        for _ in 0..instance.num_variables {
            let (next, folded) = SumcheckRound::run(transcript, &claim, table.as_ref())?;
            claim = next;
            table = folded;
        }
        Ok(claim)
    }
}

// --- the official vector ----------------------------------------------------
// fiat-shamir/turboshake128/sumcheck

const TAG: &[u8] = b"sumcheck";
const NARG: &str = "55550000555500006ff9a71d4decf758430dfb69f9c6b5359d8ab2744b13d83d";
const FINAL_EVALUATION: u32 = 0x6540_28db;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn setup() -> (spongefish::SessionId, Claim, Vec<M31>) {
    (
        spongefish::derive_session_id::<StdHash>(TAG),
        Claim {
            num_variables: 4,
            claimed_sum: M31(0xffff),
        },
        (0..16).map(|i| M31(1u32 << i)).collect(),
    )
}

#[test]
fn matches_the_cfrg_vector() {
    let (sid, instance, table) = setup();
    let (narg, output) = Narg::prove::<Sumcheck>(&sid, &instance, &table).expect("prover");
    assert_eq!(narg, hex(NARG), "NARG string differs from the CFRG vector");
    assert_eq!(output, M31(FINAL_EVALUATION));
    assert_eq!(
        Narg::verify::<Sumcheck>(&sid, &instance, &narg).expect("must verify"),
        M31(FINAL_EVALUATION)
    );
}

/// fiat-shamir/turboshake128/sumcheck_reject_trailing_bytes
#[test]
fn rejects_trailing_bytes() {
    let (sid, instance, _) = setup();
    let mut narg = hex(NARG);
    narg.push(0);
    assert!(Narg::verify::<Sumcheck>(&sid, &instance, &narg).is_err());
}

/// The decisive composition test: the same protocol written as one flat body
/// and as a nested pair must produce the identical transcript. Nesting is a
/// source-level device, not a transcript-level one.
#[test]
fn nesting_does_not_change_the_transcript() {
    let (sid, instance, table) = setup();
    let (narg, output) = Narg::prove::<NestedSumcheck>(&sid, &instance, &table).expect("prover");
    assert_eq!(narg, hex(NARG), "nesting changed the NARG string");
    assert_eq!(output, M31(FINAL_EVALUATION));
    assert_eq!(
        Narg::verify::<NestedSumcheck>(&sid, &instance, &narg).unwrap(),
        M31(FINAL_EVALUATION)
    );
}
