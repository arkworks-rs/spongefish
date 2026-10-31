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
