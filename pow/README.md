# Fiat–Shamir with proof-of-work for verifier messages

This crate is an extension of the Sponge FiSh library that provides support for challenges computed via grinding or proof-of-work mechanisms.
It allows proof-of-work-based challenge generation within multi-round public coin protocols.

## Security disclaimer and expectations

⚠️⚠️⚠️⚠️ THIS CRATE IS AN EXPERIMENT AND NOT READY FOR PRODUCTION USE ⚠️⚠️⚠️⚠️

It has not been reviewed, and should be considered a proof-of-concept example that does not make any claim about security.

## Wiring into a NARG

This crate grinds and verifies nonces over a 32-byte challenge and knows nothing about sponges. 
The caller is responsible for connecting it to the Fiat–Shamir transformation, and the pattern below is the one to follow.

The prover squeezes a challenge from its state, grinds a nonce for it, and then sends that nonce as an ordinary prover message. The verifier squeezes the same challenge, reads the nonce from the proof, and re-checks it.

```rust,ignore
use spongefish::{ProverState, StdHash, VerifierState};
use spongefish_pow::{
    blake3::Blake3PoW,
    convenience::{grind_pow, verify_pow},
};

// Fixed by the protocol, never read from the proof.
const POW_BITS: f64 = 20.0;

let session_id = spongefish::derive_session_id::<StdHash>(b"example-v00/grinding");

// Prover.
let mut prover = ProverState::<StdHash>::new(&session_id, &instance);
// ... earlier prover messages go here ...

// Squeeze the 32-byte grinding challenge.
let challenge = prover.verifier_message::<[u8; 32]>();
let solution = grind_pow::<Blake3PoW>(challenge, POW_BITS).expect("no nonce found");

// The nonce is a prover message: it MUST be absorbed.
prover.prover_message(&solution.nonce);

// ... the rest of the protocol continues from the post-nonce state ...
let narg_string = prover.narg_string();

// Verifier.
let mut verifier = VerifierState::<StdHash>::new(&session_id, &instance, narg_string);
// ... read the earlier prover messages in the same order ...

// Same squeeze, same challenge.
let challenge = verifier.verifier_message::<[u8; 32]>();

// Reading the nonce absorbs it, keeping both in lockstep.
let nonce = verifier.prover_message::<u64>().expect("unable to read the nonce");

assert!(verify_pow::<Blake3PoW>(challenge, POW_BITS, nonce));
```

Note that the nonce is absorbed as a prover message. The difficulty must be set by the protocol.
