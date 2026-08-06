//! Test vectors of draft-irtf-cfrg-fiat-shamir for the SHAKE128 and
//! TurboSHAKE128 duplex sponges ([`spongefish::instantiations`]).
//!
//! The JSON files under `tests/spec/vectors/` are vendored verbatim from the
//! specification repository (`poc/vectors/`); `vendored_vectors_are_fresh`
//! fails if they drift from the spec copy when the spec repo is checked out
//! alongside this one.

#![cfg(feature = "turboshake128")]

use serde::Deserialize;
use spongefish::{
    derive_session_id,
    instantiations::{Shake128, TurboShake128},
    DuplexSpongeInit,
};

const SHAKE128_VECTORS: &str = include_str!("spec/vectors/fiatShamirShake128Vectors.json");
const TURBOSHAKE128_VECTORS: &str =
    include_str!("spec/vectors/fiatShamirTurboShake128Vectors.json");

/// Total records per suite file, and how many this harness executes.
///
/// Of the 13 records, 9 are `DuplexSponge` traces, 1 is `DeriveSessionID`, and
/// 1 is `DecodeUint` (whose sponge trace is replayed here; the field reduction
/// pinned by its `Challenge` needs P-256 arithmetic and is exercised
/// downstream). The remaining 2 are `Sumcheck` records, which need Mersenne31
/// arithmetic and are likewise exercised by consumers. The exact counts are
/// asserted so silently skipped records fail loudly.
const TOTAL_RECORDS: usize = 13;
const EXECUTED_RECORDS: usize = 11;

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Function")]
    function: String,
    #[serde(rename = "SessionId", default)]
    session_id: Option<String>,
    #[serde(rename = "Tag", default)]
    tag: Option<String>,
    #[serde(rename = "Operations", default)]
    operations: Vec<Operation>,
    #[serde(rename = "Output")]
    output: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Operation {
    Absorb { data: String },
    Squeeze { length: usize },
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in vector file")
}

fn run_vectors<S: DuplexSpongeInit>(json: &str) {
    let vectors: Vec<Vector> = serde_json::from_str(json).expect("valid vector JSON");
    assert_eq!(vectors.len(), TOTAL_RECORDS, "unexpected vector count");
    let mut executed = 0;
    for vector in &vectors {
        match vector.function.as_str() {
            "DuplexSponge" | "DecodeUint" => {
                let session_id: [u8; 32] = unhex(vector.session_id.as_ref().expect("session id"))
                    .try_into()
                    .expect("32-byte session id");
                let mut sponge = S::init(&session_id);
                let mut squeezed = Vec::new();
                for op in &vector.operations {
                    match op {
                        Operation::Absorb { data } => {
                            sponge.absorb(&unhex(data));
                        }
                        Operation::Squeeze { length } => {
                            let mut buf = vec![0u8; *length];
                            sponge.squeeze(&mut buf);
                            squeezed.extend_from_slice(&buf);
                        }
                    }
                }
                let expected = unhex(vector.output.as_ref().expect("output"));
                assert_eq!(squeezed, expected, "vector {}", vector.name);
                executed += 1;
            }
            "DeriveSessionID" => {
                let tag = unhex(vector.tag.as_ref().expect("tag"));
                let expected = unhex(vector.output.as_ref().expect("output"));
                assert_eq!(
                    derive_session_id::<S>(&tag).as_slice(),
                    expected,
                    "vector {}",
                    vector.name
                );
                executed += 1;
            }
            // Sumcheck vectors require field arithmetic; exercised by consumers.
            "Sumcheck" => {}
            other => panic!("unknown vector function {other}"),
        }
    }
    assert_eq!(
        executed, EXECUTED_RECORDS,
        "expected to execute exactly {EXECUTED_RECORDS} vectors"
    );
}

#[test]
fn shake128_spec_vectors() {
    run_vectors::<Shake128>(SHAKE128_VECTORS);
}

#[test]
fn turboshake128_spec_vectors() {
    run_vectors::<TurboShake128>(TURBOSHAKE128_VECTORS);
}

/// When the specification repository is checked out next to this one, the
/// vendored vector files must be byte-identical to its copies.
#[test]
fn vendored_vectors_are_fresh() {
    let spec_vectors = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../draft-irtf-cfrg-sigma-protocols/poc/vectors");
    if !spec_vectors.is_dir() {
        eprintln!("spec repo not present; skipping freshness check");
        return;
    }
    for (vendored, name) in [
        (SHAKE128_VECTORS, "fiatShamirShake128Vectors.json"),
        (TURBOSHAKE128_VECTORS, "fiatShamirTurboShake128Vectors.json"),
    ] {
        let spec_copy = std::fs::read_to_string(spec_vectors.join(name))
            .unwrap_or_else(|e| panic!("cannot read spec copy of {name}: {e}"));
        assert_eq!(
            vendored, spec_copy,
            "{name} drifted from the spec repository; re-vendor it"
        );
    }
}
