# Fiat–Shamir with proof-of-work for verifier messages

This crate is an extension of spongefish for grinding or proof-of-work mechanisms in multi-round public coin protocols.

## Security disclaimer and expectations

⚠️⚠️⚠️⚠️ THIS CRATE IS AN EXPERIMENT AND NOT READY FOR PRODUCTION USE ⚠️⚠️⚠️⚠️

It has not been reviewed, and should be considered a proof-of-concept example that does not make any claim about security.

## Wiring into a NARG

The `PowTranscriptExt` extension adds a proof-of-work step to every `Transcript`. It works both inside a generic `Argument::run` and directly on `ProverState` and `VerifierState`. Both sides return `Result<T, VerificationError>`. The standalone `PoWGrinder` and convenience functions remain available for other integrations.

Both parties exchange a nonce, check bytes squeezed from the transcript sponge, then derive the protected verifier message. Only the prover searches, through `Transcript::verifier_message_oracle`. A rejected or truncated nonce poisons the verifier.

The search is sequential. The `parallel` feature (on by default) adds `verifier_message_pow_parallel(&mut prover, bits)` for provers whose public sponge is `Send`; it writes the same proof, so verifiers use `verifier_message_pow`.

Use the default features of `spongefish` and `spongefish-pow` for this example:

```rust
use spongefish::{DefaultHash, Narg, ProverState, VerificationError, VerifierState};
use spongefish_pow::PowTranscriptExt;

// Fixed by the protocol, never read from the proof.
const POW_BITS: u32 = 8;

fn main() -> Result<(), VerificationError> {
    let session_id = Narg::derive_session_id(b"example/v1/sponge-pow-8/u32");
    let instance = 0u32;

    let mut prover = ProverState::<DefaultHash>::new(&session_id, &instance);
    let challenge = prover.verifier_message_pow::<u32>(POW_BITS)?;
    let proof = prover.into_narg_string();

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof);
    let replay = verifier.verifier_message_pow::<u32>(POW_BITS)?;
    assert_eq!(challenge, replay);
    verifier.check_eof()
}
```

The same method is available with only a `Transcript` bound, so an interactive argument can use it directly:

```rust
use spongefish::{Argument, Transcript, VerificationError, Witness};
use spongefish_pow::PowTranscriptExt;

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
        transcript.verifier_message_pow::<u32>(8)
    }
}
```

Difficulty is an integer from 0 to 57. The nonce is encoded as canonical LEB128 below `2^(bits + 7)`; at zero difficulty no nonce or check bytes are used. The duplex sponge backend, difficulty, placement of the step, and returned message type must be fixed by the protocol and accounted for in its session tag. The example uses a cheap difficulty for demonstration; the appropriate work factor and soundness benefit depend on the protocol.

All PoW APIs take difficulty as `u32` and use `u64` nonces. `verifier_message_pow` accepts at most 57 bits, so its nonce space holds 128 times the expected search; the standalone BLAKE3 and Keccak strategies accept up to 59.
