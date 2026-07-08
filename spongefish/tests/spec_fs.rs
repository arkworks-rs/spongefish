//! Test vectors of draft-irtf-cfrg-fiat-shamir for the SHAKE128 and
//! TurboSHAKE128 duplex sponges ([`spongefish::instantiations::dsfs`]).
//!
//! The JSON files under `tests/spec/vectors/` are vendored verbatim from the
//! specification repository (`poc/vectors/`); `vendored_vectors_are_fresh`
//! fails if they drift from the spec copy when the spec repo is checked out
//! alongside this one.

use serde::Deserialize;
use spongefish::instantiations::dsfs::{KeccakDuplexSponge, Shake128, TurboShake128};

const SHAKE128_VECTORS: &str = include_str!("spec/vectors/fiatShamirShake128Vectors.json");
const TURBOSHAKE128_VECTORS: &str =
    include_str!("spec/vectors/fiatShamirTurboShake128Vectors.json");

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

fn run_vectors<const ROUNDS: usize>(json: &str) {
    let vectors: Vec<Vector> = serde_json::from_str(json).expect("valid vector JSON");
    let mut executed = 0;
    for vector in &vectors {
        match vector.function.as_str() {
            "DuplexSponge" | "DecodeUint" => {
                let session_id: [u8; 32] = unhex(vector.session_id.as_ref().expect("session id"))
                    .try_into()
                    .expect("32-byte session id");
                let mut sponge = KeccakDuplexSponge::<ROUNDS>::new(&session_id);
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
                let got = KeccakDuplexSponge::<ROUNDS>::derive_session_id(&tag);
                assert_eq!(got.as_slice(), expected, "vector {}", vector.name);
                executed += 1;
            }
            // Sumcheck vectors require field arithmetic; exercised by consumers.
            _ => {}
        }
    }
    assert!(executed >= 9, "expected to execute most vectors, ran {executed}");
}

#[test]
fn shake128_spec_vectors() {
    // Type-level pin: the SHAKE128 suite is the 24-round sponge.
    let _: &Shake128 = &KeccakDuplexSponge::<24>::new(&[0u8; 32]);
    run_vectors::<24>(SHAKE128_VECTORS);
}

#[test]
fn turboshake128_spec_vectors() {
    let _: &TurboShake128 = &KeccakDuplexSponge::<12>::new(&[0u8; 32]);
    run_vectors::<12>(TURBOSHAKE128_VECTORS);
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
