# Fiat–Shamir with proof-of-work for verifier messages

This crate is an extension of the Sponge FiSh library that provides support for challenges computed via grinding or proof-of-work mechanisms.
It allows proof-of-work-based challenge generation within multi-round public coin protocols.

## Security disclaimer and expectations

⚠️⚠️⚠️⚠️ THIS CRATE IS AN EXPERIMENT AND NOT READY FOR PRODUCTION USE ⚠️⚠️⚠️⚠️

It has not been reviewed, and should be considered a proof-of-concept example that does not make any claim about security.

## Wiring into a NARG

The `PowTranscriptExt` extension adds a proof-of-work step to every `Transcript`. It works both inside a generic `Argument::run` and directly on `ProverState` and `VerifierState`. Both sides return `Result<T, VerificationError>`. The standalone `PoWGrinder` and convenience functions remain available for other integrations.

Both parties execute the same protocol: obtain a 32-byte grinding challenge, exchange a nonce, check it, then obtain the protected verifier message. `Transcript::prover_only` runs the nonce search only on the prover. A rejected or truncated nonce poisons the verifier, so later checks, message reads, and the end-of-input check fail even if the error is caught.

Use the default features of `spongefish` and `spongefish-pow` for this example:

```rust
use spongefish::{DefaultHash, Narg, ProverState, VerificationError, VerifierState};
use spongefish_pow::{blake3::Blake3PoW, PowTranscriptExt};

// Fixed by the protocol, never read from the proof.
const POW_BITS: f64 = 8.0;

fn main() -> Result<(), VerificationError> {
    let session_id = Narg::derive_session_id(b"example/v1/blake3-pow-8/u32");
    let instance = 0u32;

    let mut prover = ProverState::<DefaultHash>::new(&session_id, &instance);
    let challenge = prover.verifier_message_pow::<u32, Blake3PoW>(POW_BITS)?;
    let proof = prover.into_narg_string();

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof);
    let replay = verifier.verifier_message_pow::<u32, Blake3PoW>(POW_BITS)?;
    assert_eq!(challenge, replay);
    verifier.check_eof()
}
```

The same method is available with only a `Transcript` bound, so an interactive argument can use it directly:

```rust
use spongefish::{Argument, Transcript, VerificationError, Witness};
use spongefish_pow::{blake3::Blake3PoW, PowTranscriptExt};

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
        transcript.verifier_message_pow::<u32, Blake3PoW>(8.0)
    }
}
```

The nonce is encoded as a little-endian `u64`. The PoW strategy, difficulty, placement of the step, and returned message type must be fixed by the protocol and accounted for in its session tag. The example uses a cheap difficulty for demonstration; the appropriate work factor and soundness benefit depend on the protocol.
