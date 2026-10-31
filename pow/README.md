# Fiat–Shamir with proof-of-work for verifier messages

This crate is an extension of spongefish for grinding or proof-of-work mechanisms in multi-round public coin protocols.

## Security disclaimer and expectations

⚠️⚠️⚠️⚠️ THIS CRATE IS AN EXPERIMENT AND NOT READY FOR PRODUCTION USE ⚠️⚠️⚠️⚠️

It has not been reviewed, and should be considered a proof-of-concept example that does not make any claim about security.

## Wiring into a NARG

The `PowTranscriptExt` extension adds a proof-of-work step to every `Transcript`. It works both inside a generic `Argument::run` and directly on `ProverState` and `VerifierState`. Both sides return `Result<T, VerificationError>`. The standalone `PoWGrinder` and convenience functions remain available for other integrations.

Both parties execute the same protocol: obtain a 32-byte grinding challenge, exchange a nonce, check it, then obtain the protected verifier message. `Transcript::prover_only` runs the nonce search only on the prover. A rejected or truncated nonce poisons the verifier.

This revision includes no built-in strategy. Implement `PowStrategy` for a custom construction.

The nonce is encoded as a little-endian `u64`. The PoW strategy, difficulty, placement of the step, and returned message type must be fixed by the protocol and accounted for in its session tag. The example uses a cheap difficulty for demonstration; the appropriate work factor and soundness benefit depend on the protocol.
