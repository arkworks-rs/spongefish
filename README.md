# spongefish: a duplex sponge Fiat–Shamir library 🧽🐟

Sponge FiSh (duplex **sponge** **Fi**at–**Sh**amir) is a permutation-agnostic Fiat–Shamir library that believes in random oracles. 

It implements duplex sponges for bytes (or prime fields) spec-compatible with [draft-irtf-cfrg-fiat-shamir](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/).

## Quickstart

The simplest way to start is defining an interactive `Argument`, and then compile it with `Narg`. As an example, here is the sumcheck for multilinear polynomials over the Mersenne prime field of size 2^31 - 1:

```rust
use spongefish::{Argument, Codec, Narg, Transcript, VerificationError, Witness};

const P: u64 = (1 << 31) - 1;

/// A field element, with the codecs of its `u32` representation.
#[derive(Clone, Copy, PartialEq, Debug, Codec)]
struct M31(u32);

impl M31 {
    fn add(self, other: Self) -> Self {
        Self(((u64::from(self.0) + u64::from(other.0)) % P) as u32)
    }
    fn sub(self, other: Self) -> Self {
        Self(((u64::from(self.0) + P - u64::from(other.0)) % P) as u32)
    }
    fn mul(self, other: Self) -> Self {
        Self(((u64::from(self.0) * u64::from(other.0)) % P) as u32)
    }
}

/// The sumcheck for a multilinear polynomial, given by its evaluations over {0, 1}^n.
struct Sumcheck;

impl Argument for Sumcheck {
    type Instance = (u32, M31); // (number of variables, claimed sum)
    type Witness = Vec<M31>; // the evaluations, the first variable in the low bit of the index
    type Output = M31; // the evaluation at the sampled point

    fn run<T: Transcript>(
        transcript: &mut T,
        instance: &Self::Instance,
        witness: Witness<&Self::Witness>,
    ) -> Result<M31, VerificationError> {
        let (num_variables, claimed_sum) = *instance;
        let mut table = witness.map(Clone::clone); // folded round by round, by the prover only
        let mut claim = claimed_sum;
        for _ in 0..num_variables {
            let polynomial = table.as_ref().map(|t| round_polynomial(t));
            let [a0, a1] = transcript.prover_message(polynomial)?;
            transcript.check(|| a0.add(a0).add(a1) == claim)?;
            let r: M31 = transcript.verifier_message();
            claim = a0.add(a1.mul(r));
            table = table.map(|t| fold(&t, r));
        }
        Ok(claim)
    }
}

/// The round polynomial `a0 + a1 X`: the table summed over all variables but the first.
fn round_polynomial(table: &[M31]) -> [M31; 2] {
    let (mut even, mut odd) = (M31(0), M31(0));
    for [p0, p1] in table.as_chunks::<2>().0 {
        (even, odd) = (even.add(*p0), odd.add(*p1));
    }
    [even, odd.sub(even)]
}

/// The table with its first variable fixed to `r`.
fn fold(table: &[M31], r: M31) -> Vec<M31> {
    let pairs = table.as_chunks::<2>().0;
    pairs
        .iter()
        .map(|[p0, p1]| p0.add(r.mul(p1.sub(*p0))))
        .collect()
}

// The tag identifies the protocol, the codecs, and the application context.
let tag = b"example-v00/sumcheck-m31";
let table: Vec<M31> = (0..16).map(|i| M31(1 << i)).collect();
let instance = (4, M31(0xffff)); // four variables; the table sums to 2^16 - 1

let (narg, evaluation) = Narg::prove::<Sumcheck>(tag, &instance, &table).unwrap();
assert_eq!(Narg::verify::<Sumcheck>(tag, &instance, &narg).unwrap(), evaluation);
```

`Witness` values exist only for the prover; `prover_message` turns them into plain values that both prover and verifier can use, `verifier_message` squeezes a challenge, and `check` runs a verification equation. Whatever `run` returns, here the claim left after the last round, is the output of both `Narg::prove` and `Narg::verify`. `sample` draws private randomness for protocols that need it.

The session identifier is automatically derived from the tag, and the verifier must consume the whole NARG string. An unused challenge is a compile error.

Prover and verifier messages, as well as the instance, must have associated codecs: `Encoding` to absorb a value and write it to the NARG string, `NargDeserialize` to parse it back, and `Decoding` to turn squeezed bytes into a challenge. Fixed-width integers, byte arrays, and tuples come with codecs, `#[derive(Codec)]` composes them, and `LengthPrefixed` frames variable-length sequences. The codec derived above is the one of `u32`: the verifier accepts non-canonical encodings of a field element, and challenges are reduced by the arithmetic rather than when decoded. The [sumcheck integration test](spongefish/tests/sumcheck.rs) hand-writes codecs that reject them instead, and checks this protocol against the test vector of draft-irtf-cfrg-fiat-shamir.


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

A `PermutationRelation` is a `Permutation` over wires: each call the sponge makes to it becomes a query of the instance it compiles to. A `PermutationWitnessBuilder` around the real permutation records the trace, the witness for that instance. The same sponge code runs over either:

```rust
use spongefish::{instantiations::KeccakF1600, DuplexSponge, DuplexSpongeInterface};
use spongefish_circuit::{PermutationRelation, PermutationWitnessBuilder};

// Natively, recording the trace.
let tracer = PermutationWitnessBuilder::<KeccakF1600, 200>::new(KeccakF1600);
let mut sponge = DuplexSponge::<_, 200, 136>::from(tracer.clone());
let digest: [u8; 32] = sponge.absorb(b"hello").squeeze_array();

// Symbolically: the preimage is a secret wire, the digest is public.
let relation = PermutationRelation::<u8, 200>::labeled("keccak-f[1600]");
let preimage = relation.allocate_vars::<5>();
let mut sponge = DuplexSponge::<_, 200, 136>::from(relation.clone());
let digest_wires: [_; 32] = sponge.absorb(&preimage).squeeze_array();
relation.set_vars(digest_wires, digest);

let instance = relation.compile().unwrap();
assert!(instance.is_witness_valid(&KeccakF1600, &tracer.snapshot()));
```

Linear equations over the wires, such as the XORs of a duplex cipher, are added with `add_equation`.

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
