//! Hot-path benchmarks: the codec layer, the prover/verifier drivers, and the
//! duplex-sponge instantiations.
//!
//! Run with `cargo bench -p spongefish --all-features`.

#[path = "bench_util.rs"]
mod bench_util;

use std::hint::black_box;

use bench_util::{bench, sink};
use spongefish::{
    derive_session_id,
    instantiations::{Hash, Keccak, KeccakF1600, Shake128, TurboShake128},
    Codec, DuplexSpongeInit, DuplexSpongeInterface, Encoding, LengthPrefixed, NargDeserialize,
    NargSerialize, Permutation, ProverState, StdHash, VerifierState,
};

/// A round message of the shape a real prover sends: a couple of group-element
/// sized fields plus a scalar.
#[derive(Codec, Debug, Default, Clone, Copy)]
struct RoundMessage {
    commitment: [u8; 32],
    blinder: [u8; 32],
    index: u32,
}

/// A wide message, past any plausible inline buffer.
#[derive(Codec, Debug, Clone, Copy)]
struct WideMessage {
    a: [u8; 32],
    b: [u8; 32],
    c: [u8; 32],
    d: [u8; 32],
    e: [u8; 32],
    f: [u8; 32],
}

impl Default for WideMessage {
    fn default() -> Self {
        Self {
            a: [1; 32],
            b: [2; 32],
            c: [3; 32],
            d: [4; 32],
            e: [5; 32],
            f: [6; 32],
        }
    }
}

/// Force the encoded bytes to be materialized.
///
/// `sink(encoded.as_ref().len())` is not enough: for a fixed-width codec the
/// length is a compile-time constant, so LLVM deletes the encoding entirely and
/// the benchmark measures nothing. Passing the *slice* through `black_box`
/// makes the buffer escape, so it has to be written.
fn measure_encode<T: Encoding<[u8]> + ?Sized>(value: &T) {
    let encoded = value.encode();
    black_box(encoded.as_ref());
}

fn codec_benches() {
    println!("\n== codecs (encode only) ==");
    let scalar = 0x1234_5678u32;
    bench("encode/u32", || measure_encode(&scalar));

    let pair = (0x1234_5678u32, 0x9abc_def0_1234_5678u64);
    bench("encode/(u32,u64)", || measure_encode(&pair));

    let triple = (1u32, 2u64, 3u128);
    bench("encode/(u32,u64,u128)", || measure_encode(&triple));

    let array = [0x1234_5678u32; 8];
    bench("encode/[u32; 8]", || measure_encode(&array));

    let bytes32 = [7u8; 32];
    bench("encode/[u8; 32]", || measure_encode(&bytes32));

    let label = "spongefish/bench/label";
    bench("encode/str", || measure_encode(&label));

    let round = RoundMessage::default();
    bench("encode/derive(68 B struct)", || {
        measure_encode(&round);
    });

    let wide = WideMessage::default();
    bench("encode/derive(192 B struct)", || {
        measure_encode(&wide);
    });

    let values: Vec<u32> = (0..64).collect();
    bench("encode/LengthPrefixed(&[u32; 64])", || {
        measure_encode(&LengthPrefixed(&values[..]));
    });

    println!("\n== NARG serialization ==");
    let mut narg = Vec::with_capacity(1 << 16);
    bench("serialize/derive(68 B struct)", || {
        narg.clear();
        round.serialize_into_narg(&mut narg);
    });

    println!("\n== NARG deserialization ==");
    let mut buf = Vec::new();
    round.serialize_into_narg(&mut buf);
    bench("deserialize/derive(68 B struct)", || {
        let mut cursor = &buf[..];
        sink(RoundMessage::deserialize_from_narg(&mut cursor));
    });

    let mut bytes_buf = Vec::new();
    bytes32.serialize_into_narg(&mut bytes_buf);
    bench("deserialize/[u8; 32]", || {
        let mut cursor = &bytes_buf[..];
        sink(<[u8; 32]>::deserialize_from_narg(&mut cursor));
    });

    let mut array_buf = Vec::new();
    array.serialize_into_narg(&mut array_buf);
    bench("deserialize/[u32; 8]", || {
        let mut cursor = &array_buf[..];
        sink(<[u32; 8]>::deserialize_from_narg(&mut cursor));
    });
}

fn sponge_benches() {
    println!("\n== duplex sponges ==");
    let sid = [9u8; 32];

    macro_rules! sponge_suite {
        ($name:literal, $ty:ty) => {{
            bench(concat!("sponge/", $name, "/init"), || {
                sink(<$ty>::init(&sid).squeeze_array::<1>());
            });

            let mut sponge = <$ty>::init(&sid);
            let msg = [3u8; 32];
            bench(concat!("sponge/", $name, "/absorb 32 B"), || {
                sponge.absorb(&msg);
            });

            let mut sponge = <$ty>::init(&sid);
            sponge.absorb(b"seed");
            let mut out = [0u8; 32];
            bench(concat!("sponge/", $name, "/squeeze 32 B"), || {
                sponge.squeeze(&mut out);
            });

            let mut sponge = <$ty>::init(&sid);
            sponge.absorb(b"seed");
            let mut big = vec![0u8; 4096];
            bench(concat!("sponge/", $name, "/squeeze 4 KiB"), || {
                sponge.squeeze(&mut big);
            });

            let mut sponge = <$ty>::init(&sid);
            sponge.absorb(b"seed");
            let mut big = vec![0u8; 4096];
            bench(
                concat!("sponge/", $name, "/squeeze 4 KiB in 7 B chunks"),
                || {
                    for chunk in big.chunks_mut(7) {
                        sponge.squeeze(chunk);
                    }
                },
            );

            let mut sponge = <$ty>::init(&sid);
            let msg = [3u8; 32];
            let mut out = [0u8; 32];
            bench(
                concat!("sponge/", $name, "/absorb 32 B; squeeze 32 B"),
                || {
                    sponge.absorb(&msg).squeeze(&mut out);
                },
            );
        }};
    }

    sponge_suite!("turboshake128", TurboShake128);
    sponge_suite!("shake128", Shake128);
    sponge_suite!("keccak-duplex", Keccak);
    sponge_suite!("sha256-digest", Hash<sha2::Sha256>);

    println!("\n== raw permutation ==");
    let mut state = [0u8; 200];
    bench("permutation/keccak-f1600 permute_mut", || {
        KeccakF1600.permute_mut(&mut state);
    });
    bench("permutation/keccak-f1600 permute", || {
        sink(KeccakF1600.permute(&state)[0]);
    });

    // The same permutation with no state conversion at all: the gap between
    // this and `permute_mut` above is what the 200-byte <-> 25-word round trip
    // costs on every single permutation call.
    let mut words = [0u64; 25];
    bench("permutation/keccak-f1600 raw words (no conversion)", || {
        keccak::Keccak::new().with_f1600(|f1600| f1600(&mut words));
    });
    let backend = keccak::Keccak::new();
    bench("permutation/keccak-f1600 raw words, cached backend", || {
        backend.with_f1600(|f1600| f1600(&mut words));
    });
}

fn driver_benches() {
    println!("\n== prover / verifier drivers ==");
    let sid = derive_session_id::<StdHash>(b"spongefish/bench");
    let instance = [1u8; 32];
    let seed = [0u8; 32];

    let round = RoundMessage::default();
    bench("prover/32x prover_message(derive 68 B)", || {
        let mut prover = ProverState::<StdHash>::new_with_seed(&sid, &instance, seed);
        for _ in 0..32 {
            prover.prover_message(&round);
        }
        sink(prover.narg_string().len());
    });

    bench("prover/256x prover_message(u32)", || {
        let mut prover = ProverState::<StdHash>::new_with_seed(&sid, &instance, seed);
        for i in 0..256u32 {
            prover.prover_message(&i);
        }
        sink(prover.narg_string().len());
    });

    bench("prover/256x prover_message([u8; 32])", || {
        let mut prover = ProverState::<StdHash>::new_with_seed(&sid, &instance, seed);
        for _ in 0..256 {
            prover.prover_message(&[7u8; 32]);
        }
        sink(prover.narg_string().len());
    });

    bench("prover/interleaved 32 rounds (message + challenge)", || {
        let mut prover = ProverState::<StdHash>::new_with_seed(&sid, &instance, seed);
        for _ in 0..32 {
            prover.prover_message(&round);
            let challenge: [u8; 16] = prover.verifier_message();
            sink(challenge[0]);
        }
        sink(prover.narg_string().len());
    });

    bench("prover/private rng: 32x 32 B", || {
        let mut prover = ProverState::<StdHash>::new_with_seed(&sid, &instance, seed);
        let mut out = [0u8; 32];
        for _ in 0..32 {
            prover.rng().fill_bytes(&mut out);
        }
        sink(out[0]);
    });

    // Build a NARG string once, then measure the verifier replaying it.
    let mut prover = ProverState::<StdHash>::new_with_seed(&sid, &instance, seed);
    for _ in 0..32 {
        prover.prover_message(&round);
        let challenge: [u8; 16] = prover.verifier_message();
        sink(challenge[0]);
    }
    let narg = prover.narg_string().to_vec();

    bench("verifier/interleaved 32 rounds", || {
        let mut verifier = VerifierState::<StdHash>::new(&sid, &instance, &narg);
        for _ in 0..32 {
            let msg: RoundMessage = verifier.prover_message().unwrap();
            sink(msg.index);
            let challenge: [u8; 16] = verifier.verifier_message();
            sink(challenge[0]);
        }
    });

    // Isolates `Decoding::Repr::default()`: `verifier_message` zeroes a buffer
    // that the squeeze then overwrites in full. Compare against
    // `sponge/turboshake128/squeeze 32 B`, which squeezes the same 32 bytes
    // into a buffer that is never zeroed.
    let mut prover = ProverState::<StdHash>::new_with_seed(&sid, &instance, seed);
    bench("verifier/verifier_message::<[u8; 32]>", || {
        let challenge: [u8; 32] = prover.verifier_message();
        sink(challenge[0]);
    });

    bench("session/derive_session_id", || {
        sink(derive_session_id::<StdHash>(b"spongefish/bench"));
    });
}

/// A realistic sigma-protocol prover: the group arithmetic a real proof
/// system does, alongside the codec work.
///
/// This is the benchmark that answers "does the codec layer matter?" — the
/// per-round variable-base scalar multiplication is the dominant real cost,
/// and the derived-struct message is the codec cost being optimized.
fn protocol_benches() {
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};

    println!("\n== realistic protocol (with group arithmetic) ==");
    let sid = derive_session_id::<StdHash>(b"spongefish/bench/protocol");
    let instance = [1u8; 32];
    let seed = [0u8; 32];

    bench(
        "protocol/32 rounds: scalar mult + message + challenge",
        || {
            let mut prover = ProverState::<StdHash>::new_with_seed(&sid, &instance, seed);
            let mut accumulator = RISTRETTO_BASEPOINT_POINT;
            for index in 0..32u32 {
                // The cryptographic work a real prover does per round.
                accumulator *= Scalar::from(u64::from(index) + 1);
                let message = RoundMessage {
                    commitment: accumulator.compress().to_bytes(),
                    blinder: [7u8; 32],
                    index,
                };
                prover.prover_message(&message);
                let challenge: [u8; 16] = prover.verifier_message();
                sink(challenge[0]);
            }
            sink(prover.narg_string().len());
        },
    );

    // The same loop with the group arithmetic removed, so the codec share can
    // be read off directly as the difference.
    bench("protocol/32 rounds: message + challenge only", || {
        let mut prover = ProverState::<StdHash>::new_with_seed(&sid, &instance, seed);
        for index in 0..32u32 {
            let message = RoundMessage {
                commitment: [3u8; 32],
                blinder: [7u8; 32],
                index,
            };
            prover.prover_message(&message);
            let challenge: [u8; 16] = prover.verifier_message();
            sink(challenge[0]);
        }
        sink(prover.narg_string().len());
    });

    bench("protocol/32 variable-base scalar mults only", || {
        let mut accumulator = RISTRETTO_BASEPOINT_POINT;
        for index in 0..32u32 {
            accumulator *= Scalar::from(u64::from(index) + 1);
            sink(accumulator.compress().to_bytes()[0]);
        }
    });
}

fn main() {
    // `cargo bench` passes `--bench` to a `harness = false` target; ignore it
    // and treat any remaining argument as a section filter.
    let filter = std::env::args().skip(1).find(|a| !a.starts_with("--"));
    let want = |section: &str| filter.as_ref().is_none_or(|f| section.contains(f.as_str()));

    if want("codecs") {
        codec_benches();
    }
    if want("sponges") {
        sponge_benches();
    }
    if want("drivers") {
        driver_benches();
    }
    if want("protocol") {
        protocol_benches();
    }
}
