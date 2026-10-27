# Fiat–Shamir with proof-of-work for verifier messages

This crate is an extension of spongefish for grinding or proof-of-work mechanisms in multi-round public coin protocols.

## Security disclaimer and expectations

⚠️⚠️⚠️⚠️ THIS CRATE IS NOT READY FOR PRODUCTION USE ⚠️⚠️⚠️⚠️

It has not been reviewed, and should be considered a proof-of-concept example that does not make any claim about security.

## Wiring into a NARG

`PowTranscriptExt` augments the soundness in a round with proof-of-work, for any `Transcript`. Implementations can add proof of work strategies via `PowStrategy`.

```rust
use spongefish::{Transcript, VerificationError};
use spongefish_pow::{PowStrategy, PowTranscriptExt};

fn round<T: Transcript>(
    transcript: &mut T,
    config: impl PowStrategy,
) -> Result<u64, VerificationError> {
    transcript.verifier_message_pow(config)
}
```

Rayon is optional and disabled by default. Enable `spongefish-pow`'s `parallel` feature to opt into Rayon-backed search. Transcript helpers are synchronous. Parallel search may block the calling thread until the PoW step completes.

## Fused transcript proof of work

Both parties execute the same protocol: exchange a compact nonce, check bytes squeezed from the public duplex sponge, then obtain the protected verifier message. `Transcript::verifier_message_oracle` provides a prover-only evaluator, so the verifier skips the nonce search. A rejected or truncated nonce poisons the verifier. Generic `verifier_message_pow` is always sequential, including inside `Argument::run` and `Narg::prove`. The `parallel` feature adds `verifier_message_pow_parallel(&mut prover, FusedPowConfig::new(bits))` for concrete provers with a `Send` public duplex sponge. It produces the same least nonce, proof and challenge, so verification still uses the generic method. Generic search cannot reach the parallel path, because `Transcript::verifier_message_oracle` does not require a `Send` evaluator. Each trial clones the public duplex sponge and runs it on one thread without SIMD. In `v0.8.0`, `verifier_message_pow` searched a separate BLAKE3 or Keccak hash on all threads. Grinding inside `Argument::run` is therefore slower at the same difficulty: in one measurement at 20 bits with `DefaultHash` on a 10-core machine, about 35 times fewer trials per second than the `v0.8.0` BLAKE3 search (about 6 times fewer with `verifier_message_pow_parallel`). Ordinary proving, private RNGs and verification require neither `Send` nor `Sync`. The feature is opt-in; it does not change generic search behavior.

Use the default features of `spongefish` and `spongefish-pow` for this example:

```rust
use spongefish::{DefaultHash, Narg, ProverState, VerificationError, VerifierState};
use spongefish_pow::{FusedPowConfig, PowTranscriptExt};

// Fixed by the protocol, never read from the proof.
const POW_BITS: u32 = 8;

fn main() -> Result<(), VerificationError> {
    let session_id = Narg::derive_session_id(b"example/v1/sponge-pow-8/u32");
    let instance = 0u32;

    let mut prover = ProverState::<DefaultHash>::new(&session_id, &instance);
    let challenge = prover.verifier_message_pow::<u32>(FusedPowConfig::new(POW_BITS))?;
    let proof = prover.into_narg_string();

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof);
    let replay = verifier.verifier_message_pow::<u32>(FusedPowConfig::new(POW_BITS))?;
    assert_eq!(challenge, replay);
    verifier.check_eof()
}
```

The same method is available with only a `Transcript` bound, so an interactive argument can use it directly:

```rust
use spongefish::{Argument, Transcript, VerificationError, Witness};
use spongefish_pow::{FusedPowConfig, PowTranscriptExt};

struct PowRound;
impl Argument for PowRound {
    type Instance = u32;
    type Witness = ();
    type Output = u32;

    fn run<T: Transcript>(
        transcript: &mut T,
        _instance: &u32,
        _witness: Witness<&()>,
    ) -> Result<u32, VerificationError> {
        transcript.verifier_message_pow::<u32>(FusedPowConfig::new(8))
    }
}
```

Difficulty is an integer from 0 to 57. The nonce is encoded as canonical LEB128 below `2^(bits + 7)`; at zero difficulty no nonce or check bytes are used. The duplex sponge backend, difficulty, placement of the step, and returned message type must be fixed by the protocol and accounted for in its session tag. The example uses a cheap difficulty for demonstration; the appropriate work factor and soundness benefit depend on the protocol.
