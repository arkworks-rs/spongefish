# Fiat–Shamir with proof-of-work for verifier messages

This crate is an extension of the Sponge FiSh library that provides support for challenges computed via grinding or proof-of-work mechanisms.
It allows proof-of-work-based challenge generation within multi-round public coin protocols.

## Security disclaimer and expectations

⚠️⚠️⚠️⚠️ THIS CRATE IS AN EXPERIMENT AND NOT READY FOR PRODUCTION USE ⚠️⚠️⚠️⚠️

It has not been reviewed, and should be considered a proof-of-concept example that does not make any claim about security.

## Wiring into a NARG

The `DecodingPow` extension connects proof of work to byte-oriented `ProverState` and `VerifierState` transcripts. The standalone `PoWGrinder` and convenience functions remain available for other integrations.

The prover squeezes a 32-byte grinding challenge, grinds and sends a nonce, then squeezes the protected verifier message. The verifier checks the nonce before absorbing it or returning that message. A rejected or truncated nonce poisons the verifier, so subsequent reads and the end-of-input check also fail.

Use the default features of `spongefish` and `spongefish-pow` for this example:

```rust
use spongefish::{DefaultHash, Narg, ProverState, VerificationError, VerifierState};
use spongefish_pow::{blake3::Blake3PoW, DecodingPow};

// Fixed by the protocol, never read from the proof.
const POW_BITS: f64 = 8.0;

fn main() -> Result<(), VerificationError> {
    let session_id = Narg::derive_session_id(b"example/v1/blake3-pow-8/u32");
    let instance = 0u32;

    let mut prover = ProverState::<DefaultHash>::new(&session_id, &instance);
    let challenge = prover.verifier_message_pow::<u32, Blake3PoW>(POW_BITS);
    let proof = prover.into_narg_string();

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof);
    let replay = verifier.verifier_message_pow::<u32, Blake3PoW>(POW_BITS)?;
    assert_eq!(challenge, replay);
    verifier.check_eof()
}
```

The nonce is encoded as a little-endian `u64`. The PoW strategy, difficulty, placement of the step, and returned message type must be fixed by the protocol and accounted for in its session tag. The example uses a cheap difficulty for demonstration; the appropriate work factor and soundness benefit depend on the protocol.
