# spongefish: a duplex sponge Fiat–Shamir library 🧽🐟

Sponge FiSh (duplex **sponge** **Fi**at–**Sh**amir) is a permutation-agnostic Fiat–Shamir library that believes in random oracles.
It facilitates writing multi-round public-coin protocols once as an `Argument`,
then running the same body as prover or verifier.
It provides a generic API for generating the verifier's public coins and the prover's private randomness.
The project is split into several crates:

- `spongefish`: the core library implementing draft-irtf-cfrg-fiat-shamir, together with the duplex sponge API.
- `spongefish-circuit`: constraint builders for permutation-based relations.
- `spongefish-derive`: derive macros for codecs and related traits.
- `spongefish-pow`: proof‑of‑work helpers for deriving Fiat–Shamir challenges via grinding.

Hash functions can also be bridged in from Rust's generic [`Digest`](https://docs.rs/digest/latest/digest/) API and [`XofReader`](https://docs.rs/digest/latest/digest/trait.XofReader.html).

## Example

Implement the public-coin dialogue once, generic over `Transcript`, then compile
it into a non-interactive argument with `Narg`:

```rust
use spongefish::{Argument, Narg, StdHash, Transcript, VerificationResult, Witness};

struct Schnorr;

impl Argument for Schnorr {
    type Instance = [u32; 2]; // [generator, public key]
    type Witness = u32;
    type Output = ();

    fn run<T: Transcript>(
        transcript: &mut T,
        instance: &Self::Instance,
        witness: Witness<&Self::Witness>,
    ) -> VerificationResult<()> {
        let [generator, public_key] = *instance;
        let nonce = transcript.sample::<u32>();
        let commitment = transcript
            .prover_message(nonce.map(|k| generator.wrapping_mul(k)))?;
        let challenge = transcript.verifier_message::<u32>();
        let response = transcript.prover_message(
            nonce
                .zip(witness)
                .map(|(k, x)| k.wrapping_add(challenge.wrapping_mul(*x))),
        )?;
        transcript.check(|| {
            generator.wrapping_mul(response)
                == commitment.wrapping_add(challenge.wrapping_mul(public_key))
        })
    }
}

// The tag identifies the protocol, the codecs, and the application context.
let session_id = spongefish::derive_session_id::<StdHash>(b"example-v00/schnorr-u32");
let witness = 42u32;
let instance = [7, 7 * witness];

let (narg, ()) = Narg::prove::<Schnorr>(&session_id, &instance, &witness).unwrap();
Narg::verify::<Schnorr>(&session_id, &instance, &narg).unwrap();
```

## Feature flags

| Feature | Default | Description |
| --- | :-: | --- |
| `turboshake128` | ✓ | The draft's SHAKE128 and TurboSHAKE128 suites, `StdHash`, `Narg`, and `ProverState` |
| `getrandom` | ✓ | Enables OS-seeded `ProverState::new`; with `turboshake128`, also enables `Narg::prove` |
| `zeroize` | ✓ | Wipes sponge and RNG state on drop |
| `derive` | | `#[derive(Codec)]` and friends via `spongefish-derive` |
| `rand` | | `rand_core` trait adapters for `PrivateRng` |
| `keccak` | | Overwrite-mode duplex sponge over Keccak-f\[1600\] |
| `ascon` | | Overwrite-mode duplex sponge over the Ascon permutation |
| `yolocrypto` | | direct access to the duplex sponge |

## More information

See the [crate documentation](https://arkworks.rs/spongefish/), the
[Ristretto Schnorr integration test](https://github.com/arkworks-rs/spongefish/blob/main/spongefish/tests/interactive_schnorr.rs),
and the [sumcheck integration test](https://github.com/arkworks-rs/spongefish/blob/main/spongefish/tests/interactive_sumcheck.rs).

## Funding

This project was funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/sigmaprotocols).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
