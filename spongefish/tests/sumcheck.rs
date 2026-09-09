//! The sumcheck of draft-irtf-cfrg-fiat-shamir.
//!
//! This file tests sumcheck relation for multilinear polynomials in `N` variables
//! over the field of size `P = 2^31-1`.

use spongefish::{derive_session_id, Argument, DefaultHash, Narg, Transcript, Witness};
use spongefish::{ByteArray, Decoding, Encoding, NargDeserialize, NargReader, VerificationError};

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

impl Encoding for M31 {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.to_le_bytes()
    }
}

impl NargDeserialize for M31 {
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
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

impl Encoding for Claim {
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

// =============
// The protocol.
// =============

struct Sumcheck;

impl Argument for Sumcheck {
    type Instance = Claim;
    type Witness = Vec<M31>;
    type Output = M31;

    fn run<T: Transcript>(
        transcript: &mut T,
        instance: &Claim,
        witness: Witness<&Vec<M31>>,
    ) -> Result<M31, VerificationError> {
        // The prover's witness, folded across rounds.
        // The verifier will not know what `table` is.
        let mut table: Witness<Vec<M31>> = witness.map(Clone::clone);
        let mut claim = instance.claimed_sum;

        for _ in 0..instance.num_variables {
            let coefficients = table.as_ref().map(|t| round_coefficients(t));
            let a0 = transcript.prover_message(coefficients.map(|c| c.0))?;
            let a1 = transcript.prover_message(coefficients.map(|c| c.1))?;

            transcript.check(|| a0.add(a0).add(a1) == claim)?;
            let r: M31 = transcript.verifier_message();
            claim = a0.add(a1.mul(r));

            table = table.map(|t| fold(&t, r));
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
        derive_session_id::<DefaultHash>(TAG),
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
    let (narg, output) =
        Narg::prove_with_session_id::<Sumcheck>(&sid, &instance, &table).expect("prover");
    assert_eq!(narg, hex(NARG), "NARG string differs from the CFRG vector");
    assert_eq!(output, M31(FINAL_EVALUATION));
    assert_eq!(
        Narg::verify_with_session_id::<Sumcheck>(&sid, &instance, &narg).expect("must verify"),
        M31(FINAL_EVALUATION)
    );
}

/// fiat-shamir/turboshake128/sumcheck_reject_trailing_bytes
#[test]
fn rejects_trailing_bytes() {
    let (sid, instance, _) = setup();
    let mut narg = hex(NARG);
    narg.push(0);
    assert!(Narg::verify_with_session_id::<Sumcheck>(&sid, &instance, &narg).is_err());
}
