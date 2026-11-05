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

`FusedPowConfig::new(bits)` binds work directly to the current transcript sponge:

```rust
use spongefish::{Transcript, VerificationError};
use spongefish_pow::{FusedPowConfig, PowTranscriptExt};

fn round<T: Transcript>(transcript: &mut T) -> Result<u64, VerificationError> {
    transcript.verifier_message_pow(FusedPowConfig::new(8))
}
```

For positive difficulty, the prover sends the least accepted nonce as canonical LEB128 below `2^(bits + 7)`. Both roles absorb it, squeeze `ceil(bits / 8)` check bytes, check the low `bits` bits are zero, and then derive the protected verifier message. Difficulty is 0 through 57; at zero no nonce or check bytes are used. The new construction changes the proof format, so select it explicitly and update the protocol session tag.

The prover evaluates candidates on owned snapshots of the public sponge. The verifier never searches or needs an evaluator. A rejected or truncated nonce permanently rejects verification; a prover whose replay disagrees with its evaluator reports an error even in release builds, and its state must be discarded.

The default helper uses scalar sequential search, including inside generic `Argument::run`. With the `parallel` feature, on a concrete prover with a `Send` public sponge, `spongefish_pow::verifier_message_pow_parallel(&mut prover, FusedPowConfig::new(bits))` uses owned snapshots on the Rayon pool and produces the same proof. The private RNG stays on the calling thread and needs neither `Send` nor `Sync`. Generic `Transcript` evaluators do not promise `Send`, so this fused parallel capability cannot be used with only a generic `Transcript` bound.

For a permutation-backed sponge, a trial costs one permutation when the nonce fits the current absorb block and the check plus protected message fit in one rate block. Longer nonces, other alignments and other sponge backends can cost more.
