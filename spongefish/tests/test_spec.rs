#![cfg(feature = "sha3")]

use std::collections::HashMap;

use libtest_mimic::{Arguments, Failed, Trial};
use serde::{Deserialize, Serialize};
use spongefish::DuplexSpongeInterface;

#[derive(Debug, Deserialize, Serialize)]
struct TestVector {
    #[serde(rename = "Expected")]
    expected: String,
    #[serde(rename = "HashFunction")]
    hash_function: String,
    #[serde(rename = "Operations")]
    operations: Vec<Operation>,
    #[serde(rename = "IV")]
    iv: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Operation {
    #[serde(rename = "type")]
    op_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    length: Option<usize>,
}

#[derive(Clone)]
struct Shake128Spec {
    hasher: sha3::Shake128,
}

impl Shake128Spec {
    fn new(iv: [u8; 64]) -> Self {
        use sha3::digest::Update;

        const RATE: usize = 168;
        let mut hasher = sha3::Shake128::default();
        let mut initial_block = [0u8; RATE];
        initial_block[..64].copy_from_slice(&iv);
        hasher.update(&initial_block);
        Self { hasher }
    }
}

impl DuplexSpongeInterface for Shake128Spec {
    type U = u8;

    fn absorb(&mut self, input: &[Self::U]) -> &mut Self {
        use sha3::digest::Update;
        self.hasher.update(input);
        self
    }

    fn squeeze(&mut self, output: &mut [Self::U]) -> &mut Self {
        use sha3::digest::{ExtendableOutput, XofReader};
        let mut reader = self.hasher.clone().finalize_xof();
        reader.read(output);
        self
    }

    fn ratchet(&mut self) -> &mut Self {
        self
    }
}

fn hex_decode(hex_str: &str) -> Vec<u8> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
        .collect()
}

fn load_test_vectors() -> HashMap<String, TestVector> {
    let json_data = include_str!("./spec/vectors/duplexSpongeVectors.json");
    serde_json::from_str(json_data).expect("Failed to parse test vectors JSON")
}

fn run_test_vector(name: &str, test_vector: &TestVector) -> Result<(), Failed> {
    if test_vector.hash_function != "SHAKE128" {
        // Keccak vectors are gated until IV support is added for that instantiation.
        return Ok(());
    }

    let iv_bytes = hex_decode(&test_vector.iv);
    let iv_array: [u8; 64] = iv_bytes
        .try_into()
        .expect("IV must be exactly 64 bytes in the test vectors");

    let mut sponge = Shake128Spec::new(iv_array);
    let mut final_output = Vec::new();

    for operation in &test_vector.operations {
        match operation.op_type.as_str() {
            "absorb" => {
                if let Some(data_hex) = &operation.data {
                    let data = hex_decode(data_hex);
                    sponge.absorb(&data);
                }
            }
            "squeeze" => {
                if let Some(length) = operation.length {
                    let mut output = vec![0u8; length];
                    sponge.squeeze(&mut output);
                    final_output = output;
                }
            }
            other => {
                return Err(Failed::from(format!("Unknown operation type: {other}")));
            }
        }
    }

    if hex::encode(final_output) == test_vector.expected {
        Ok(())
    } else {
        Err(Failed::from(format!("Test vector '{name}' failed")))
    }
}

#[test]
fn test_all_duplex_sponge_vectors() {
    let tests = load_test_vectors()
        .into_iter()
        .filter(|(_, test_vector)| test_vector.hash_function == "SHAKE128")
        .map(|(name, test_vector)| {
            Trial::test(
                format!("tests::spec::test_duplex_sponge::{name}"),
                move || run_test_vector(&name, &test_vector),
            )
        })
        .collect();

    libtest_mimic::run(&Arguments::from_args(), tests).exit();
}
