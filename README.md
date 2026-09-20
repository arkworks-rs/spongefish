# spongefish: a duplex sponge Fiat–Shamir library 🧽🐟

Sponge FiSh (duplex **sponge** **Fi**at–**Sh**amir) is a permutation-agnostic Fiat–Shamir library that believes in random oracles. 

It implements duplex sponges for bytes (or prime fields) spec-compatible with [draft-irtf-cfrg-fiat-shamir](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/).

## Quickstart

The simplest way to start is defining an interactive `Argument`, and then compile it with `Narg`:

```rust
use spongefish::{Argument, Narg, Transcript, VerificationError, Witness};

struct Schnorr;

impl Argument for Schnorr {
    type Instance = [u32; 2]; // [generator, public key]
    type Witness = u32;
    type Output = ();

    fn run<T: Transcript>(
        transcript: &mut T,
        instance: &Self::Instance,
        witness: Witness<&Self::Witness>,
    ) -> Result<(), VerificationError> {
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
let tag = b"example-v00/schnorr-u32";
let witness = 42u32;
let instance = [7, 7 * witness];

let (narg, ()) = Narg::prove::<Schnorr>(tag, &instance, &witness).unwrap();
Narg::verify::<Schnorr>(tag, &instance, &narg).unwrap();
```

`Witness` values exist only for the prover; `prover_message` turns witness values into plain values that can be used both by prover and verifier. `verifier_message` squeezes a challenge, and `sample` draws a uniformly random value using the prover's private randomness. `check` runs the verification equation. 

The session identifier is automatically derived from the tag, the verifier must consume the whole NARG string. An unused challenge is a compile error. 

Each prover and verifier messages, as well as the instance, must have associated codecs. See `LengthPrefixed` and `#[derive(Codec)]` for helpers in defining new codecs.


## Crates

- `spongefish`: the core library implementing draft-irtf-cfrg-fiat-shamir, together with the duplex sponge API.
- `spongefish-circuit`: constraint builders for permutation-based relations.
- `spongefish-derive`: derive macros for codecs and related traits.
- `spongefish-pow`: proof‑of‑work helpers for deriving Fiat–Shamir challenges via grinding.

## Duplex sponge

The duplex sponge construction allows absorb and squeeze over an alphabet implementing `Unit`. This is abstracted as `DuplexSpongeInterface`.

```rust
use spongefish::{instantiations::Keccak, DuplexSpongeInterface};

/// Absorb, then squeeze as much as asked.
fn xof<S: DuplexSpongeInterface>(sponge: &mut S, input: &[S::U], len: usize) -> Box<[S::U]> {
    sponge.absorb(input).squeeze_boxed(len)
}

/// Illustrative authenticated encryption of one block.
fn encrypt<S: DuplexSpongeInterface<U = u8>>(sponge: &mut S, key: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let keystream = xof(sponge, key, plaintext.len());
    let ciphertext = plaintext.iter().zip(&keystream).map(|(p, k)| p ^ k).collect();
    let tag = sponge.absorb(plaintext).squeeze_array();
    (ciphertext, tag)
}

let digest = xof(&mut Keccak::default(), b"hello", 32);
let (ciphertext, tag) = encrypt(&mut Keccak::default(), b"key", b"attack at dawn");

// Decryption walks the same path and reaches the same tag.
let mut sponge = Keccak::default();
let keystream = xof(&mut sponge, b"key", ciphertext.len());
let plaintext: Vec<u8> = ciphertext.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
assert_eq!(plaintext, b"attack at dawn");
assert_eq!(sponge.absorb(&plaintext).squeeze_array::<16>(), tag);
```

## Hash statements

Hash preimage statements can be built via `spongefish-circuit`. 

A `PermutationRelation` yields the constraints proving correct evaluations of query-answers for a permutation oracle.
It is additionally possible to constrain the evaluations on algebraic relations: 

```rust
use spongefish::{instantiations::KeccakF1600, DuplexSponge, DuplexSpongeInterface};
use spongefish_circuit::{PermutationRelation, PermutationWitnessBuilder};

fn xof<S: DuplexSpongeInterface>(sponge: &mut S, input: &[S::U], len: usize) -> Box<[S::U]> {
    sponge.absorb(input).squeeze_boxed(len)
}

// Natively, recording the trace: the digest, then the ciphertext and tag.
let tracer = PermutationWitnessBuilder::<KeccakF1600, 200>::new(KeccakF1600);
let digest = xof(&mut DuplexSponge::<_, 200, 136>::from(tracer.clone()), b"hello", 32);
let mut sponge = DuplexSponge::<_, 200, 136>::from(tracer.clone());
let keystream = xof(&mut sponge, b"key", 14);
let ciphertext: Vec<u8> = b"attack at dawn".iter().zip(&keystream).map(|(p, k)| p ^ k).collect();
let tag: [u8; 16] = sponge.absorb(b"attack at dawn").squeeze_array();

// Symbolically: the preimage, the key and the plaintext are secret wires;
// the digest, the ciphertext and the tag are public.
let relation = PermutationRelation::<u8, 200>::labeled("keccak-f[1600]");
let preimage = relation.allocate_vars::<5>();
let out = xof(&mut DuplexSponge::<_, 200, 136>::from(relation.clone()), &preimage, 32);
relation.set_vars(out.iter(), &digest);

let key = relation.allocate_vars::<3>();
let plaintext = relation.allocate_vars::<14>();
let mut sponge = DuplexSponge::<_, 200, 136>::from(relation.clone());
let keystream = xof(&mut sponge, &key, 14);
for ((k, p), c) in keystream.iter().zip(&plaintext).zip(&ciphertext) {
    relation.add_equation(*k * 0xFF + *p, *c); // k ^ p = c
}
let tag_wires: [_; 16] = sponge.absorb(&plaintext).squeeze_array();
relation.set_vars(tag_wires, tag);

let instance = relation.compile().unwrap();
assert_eq!(instance.queries().len(), 3);
assert!(instance.is_witness_valid(&KeccakF1600, &tracer.snapshot()));
```

## Arguments with grinding

It is possible to augment the bits of soundnes with a proof of work using `spongefish-pow`:

```rust
use spongefish::{Argument, Narg, Transcript, VerificationError, Witness};
use spongefish_pow::{blake3::Blake3PoW, PowTranscriptExt};

/// A challenge the prover pays `BITS` bits of work for.
struct GrindingArgumentExample<const BITS: u32>;

impl<const BITS: u32> Argument for GrindingArgumentExample<BITS> {
    type Instance = [u8; 32]; // whatever the work is bound to
    type Witness = ();
    type Output = u64;

    fn run<T: Transcript>(
        transcript: &mut T,
        _instance: &[u8; 32],
        _witness: Witness<&()>,
    ) -> Result<u64, VerificationError> {
        transcript.verifier_message_pow::<u64, Blake3PoW>(f64::from(BITS))
    }
}

let tag = b"example-v00/grind-16";
let instance = [7u8; 32];
let (narg, challenge) = Narg::prove::<GrindingArgumentExample<16>>(tag, &instance, &()).unwrap();
assert_eq!(narg.len(), 8); // one u64 nonce
assert_eq!(Narg::verify::<GrindingArgumentExample<16>>(tag, &instance, &narg).unwrap(), challenge);
```

`verifier_message_pow` internally squeezes a grinding seed, has the prover search for a nonce solving the grinding problem, then sends the nonce as a prover message, and returns a new verifier message. A Keccak strategy is available too, and the `parallel` feature will use multi-threading the search across threads.

## Also in the box

- `FiatShamir::<H>` runs an argument over another duplex sponge: the draft's
  `Shake128` suite, overwrite-mode `Keccak` and `Ascon12` behind feature flags,
  or the `instantiations::{XOF, Hash}` bridges for RustCrypto's
  [`ExtendableOutput`](https://docs.rs/digest/latest/digest/trait.ExtendableOutput.html)
  and [`Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html).
- `ProverState` and `VerifierState` for protocols that do not fit one body,
  including a proof followed by data the caller parses itself.
- `SessionId` is a distinct type, so a tag cannot be passed where a derived
  identifier is expected; `prove_with_session_id` accepts one established
  elsewhere.
- The sponge is generic over its alphabet: `DuplexSponge` over a
  `Permutation` on field elements, such as Poseidon2, runs the whole
  transcript natively in the field, seeded through `EncodedSessionId`.

## Feature flags

| Feature | Default | Description |
| --- | :-: | --- |
| `turboshake128` | ✓ | The draft's SHAKE128 and TurboSHAKE128 suites, `DefaultHash`, `Narg`, and `ProverState` |
| `getrandom` | ✓ | Enables OS-seeded `ProverState::new`; with `turboshake128`, also enables `Narg::prove` |
| `zeroize` | ✓ | Enables sponge-state wiping where supported by the backend; standard squeeze buffers and RNG seed buffers are always wiped on drop |
| `derive` | | `#[derive(Codec)]` and friends via `spongefish-derive` |
| `rand` | | `rand_core` trait adapters for `PrivateRng` |
| `keccak` | | Overwrite-mode duplex sponge over Keccak-f\[1600\] |
| `ascon` | | Overwrite-mode duplex sponge over the Ascon permutation |
| `yolocrypto` | | direct access to the duplex sponge |

## Status

The current codebase is unaudited and the API is being redesigned; expect breaking changes until the next release. Earlier revisions were reviewed by Radically Open Security and OpenZeppelin. See [SECURITY.md](SECURITY.md) for scope and private reporting, and the [threat model](docs/threat-model.md) for security guarantees, caller responsibilities, and assurance limits.

## More information

See the [crate documentation](https://arkworks.rs/spongefish/), the [Ristretto Schnorr integration test](spongefish/tests/schnorr.rs), and the [sumcheck integration test](spongefish/tests/sumcheck.rs).

## Funding

This project was funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/sigmaprotocols).
