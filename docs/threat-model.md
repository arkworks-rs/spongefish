# Threat model

Read this with [SECURITY.md](../SECURITY.md), which defines reporting scope,
supported versions, and audit status. The current code is not externally audited.
This document describes intended guarantees, their implementation boundaries, and
assurance limits; it is not a security certification.

## Architecture and assets

Spongefish is an embedded, allocating `no_std` Rust library for transforming
public-coin interactive arguments into non-interactive arguments. It does not
operate a network service or provide authentication, key management, persistent
secret storage, or replay protection. Big-endian targets are explicitly rejected
(`spongefish/src/lib.rs:157`, `spongefish/src/lib.rs:170`).

An application supplies an `Argument`, public instance, and application tag. The
prover also supplies its witness. `Narg` derives a typed session identifier,
initializes the transcript with that identifier and encoded instance, runs the
argument, and produces a NARG byte string. Verification runs the same argument
without the witness and checks that the complete string was consumed. The
low-level `ProverState` and `VerifierState` interfaces expose each operation
separately (`spongefish/src/argument.rs:391`,
`spongefish/src/argument.rs:436`, `spongefish/src/narg_prover.rs:141`).

The assets are the binding of an accepted argument to its statement, codecs and
application context; correctly distributed challenges; the confidentiality of
witnesses, nonces and RNG state; verifier availability; and the integrity of
published crates, documentation and specification vectors.

## Attacker capabilities and trust boundaries

A malicious prover can submit arbitrary, truncated, extended or modified proof
bytes. An application may also let an adversary choose instance contents or
request sizes; the application must validate and budget those inputs. Submission
of a proof does not grant access to verifier code, private RNG state, release
credentials or the host's memory. Memory disclosure and timing observations
require additional exposure in the integrating application.

| Boundary | Library control | Caller or implementer obligation |
| --- | --- | --- |
| Proof bytes into parsing | `NargReader` uses checked reads and retains failure as a poisoned state. `read_vec` caps initial capacity at 64 elements and rejects elements that consume no input (`spongefish/src/narg_string.rs:60`, `spongefish/src/narg_string.rs:81`). | Custom deserializers must reject invalid values and noncanonical encodings, check lengths, and terminate without panicking. The reader cannot sandbox arbitrary user code. |
| Parsed messages into the transcript | The high-level byte transcript uses `prover_message_as`, which absorbs the actual consumed bytes and rejects swallowed read failures (`spongefish/src/argument.rs:337`, `spongefish/src/narg_verifier.rs:274`, `spongefish/src/narg_verifier.rs:383`). | The generic low-level `prover_message` and `prover_message_with` paths re-encode values. Their encodings must match the prover's absorption map, including for non-byte alphabets (`spongefish/src/narg_verifier.rs:79`, `spongefish/src/narg_verifier.rs:196`). |
| Transcript into acceptance | `Narg::verify` runs the argument's checks and then checks EOF. Terminal low-level helpers also check EOF (`spongefish/src/argument.rs:446`, `spongefish/src/narg_verifier.rs:293`). | An argument must check its actual verification equations. Other low-level callers must invoke `check_eof` or correctly transfer and discharge the remaining parsing obligation. Parsing success is not proof acceptance. |
| Application context into initialization | The session identifier and encoded instance seed the public transcript (`spongefish/src/narg_prover.rs:141`, `spongefish/src/narg_verifier.rs:331`). | Choose a tag identifying the non-interactive argument, codec widths and encodings, suite, and application context. Update it when these change. Validate instances and supply a secure public-coin protocol. |
| Codec/backend implementation into cryptography | Traits establish interfaces and widths; standard suites implement the specified constructions (`spongefish/src/codecs.rs:129`, `spongefish/src/duplex_sponge.rs:308`, `spongefish/src/instantiations/suites.rs:14`). | Trait implementations do not prove injectivity, prefix-freeness, negligible decoding bias, adequate sponge capacity, or cryptographic security. Custom implementations are trusted code. |
| Entropy into private sampling | OS constructors obtain a 32-byte seed. The private RNG is separate from the public transcript (`spongefish/src/private_rng.rs:54`, `spongefish/src/narg_prover.rs:61`). | The entropy source must be reliable. Deterministic constructors are for tests; seed/nonce reuse can destroy privacy. A caller-supplied backend must be suitable for secret randomness. |

`Argument` must be stateless; the high-level entry points enforce this property.
That check does not prove the argument sound or zero-knowledge
(`spongefish/src/argument.rs:264`, `spongefish/src/argument.rs:452`).
`Encoding` must be injective and prefix-free; `Decoding` must produce a uniform
or negligibly biased distribution with a sufficiently wide input. Derive fields
marked `skip` are intentionally not bound by the transcript
(`spongefish/src/codecs.rs:29`, `spongefish/src/codecs.rs:53`,
`spongefish/src/codecs.rs:94`).

## Secret lifetime and side channels

`PrivateRng` seed buffers use `Zeroizing`. Standard `ByteArray` decoding buffers
implement `ZeroizeOnDrop` and redact `Debug`, regardless of the `zeroize` feature.
Ownership transfers into decoding, so ordinary return and unwinding run their
destructors. Generated decoders borrow the outer preimage instead of creating an
extra unprotected array; standard field representations also wipe on drop
(`spongefish/src/private_rng.rs:54`, `spongefish/src/private_rng.rs:68`,
`spongefish/src/codecs.rs:219`, `derive/src/lib.rs:195`).

The default-enabled `zeroize` feature separately enables supported sponge-state
erasure. It is not a blanket guarantee for custom backends. The XOF wrapper's
`ZeroizeOnDrop` marker requires both its hasher and reader to support that marker;
the source documents the SHAKE reader's marker limitation
(`spongefish/Cargo.toml:18`, `spongefish/src/instantiations/xof.rs:141`).

Erasure does not cover the caller's witness, returned samples, `fill_bytes`
destinations, caller-held seeds, custom representation storage, or copies made
by custom decoders. Borrow preimages where possible and give owned secret copies
their own erasure policy. Moves, compiler temporaries, registers, allocator or OS
copies, process aborts, and deliberately forgotten values limit what a Rust
destructor can erase (`spongefish/src/private_rng.rs:82`,
`spongefish/src/codecs.rs:146`).

`Witness<T>` prevents direct use of unavailable prover values in shared verifier
control flow; it is not a secret-memory or constant-time container. Neither it
nor Spongefish makes arbitrary protocol arithmetic, decoders or closures
constant-time. The application must protect secret-dependent computation and
decide whether message lengths and control-flow shape may be public
(`spongefish/src/argument.rs:25`, `spongefish/src/argument.rs:50`).
Power analysis, speculative execution attacks and live process-memory compromise
are not mitigated by these buffer-wiping controls.

## Availability and conditional surfaces

For valid caller configuration and conforming codecs, every adversarial NARG
string should terminate with acceptance or `VerificationError`, never a panic.
This does not promise successful recovery from allocation failure or place a
global limit on proof size, nesting, sampling counts or runtime. A service must
bound those before exposing the library to untrusted requests. Empty encoded
instances and OS-entropy failure are documented constructor panics, rather than
malformed-proof parsing behavior (`spongefish/src/narg_verifier.rs:326`,
`spongefish/src/private_rng.rs:50`).

The experimental `spongefish-circuit`, `spongefish-pow` and `yolocrypto` surfaces
remain outside SECURITY.md's reporting scope. Circuit allocators share mutable
in-process state, not an isolated service boundary. PoW solving may search the
nonce space and use parallel workers; callers own difficulty selection, resource
limits and binding to their protocol (`circuit/src/allocator.rs:46`,
`pow/src/lib.rs:89`). The overwrite-mode Keccak/Ascon constructions must not be
treated as interchangeable with the draft's SHAKE/TurboSHAKE suites
(`spongefish/src/instantiations/suites.rs:25`).

## CI, upstream data and publication

The provenance checker reads exactly the two suite vector files under
`spongefish/tests/spec/vectors`, checks their SHA-256 values, and downloads their
counterparts from `raw.githubusercontent.com/mmaker/draft-irtf-cfrg-sigma-protocols`
at the full commit recorded in `spongefish/tests/spec/provenance.json`, under
`poc/vectors`. Missing files, download failures and byte differences fail the
check; no neighboring checkout is required. The repository and filename set are
restricted by the checker. A contributor changing the script, vectors and
metadata together still requires review: provenance establishes origin, not
independent correctness (`scripts/check-vector-provenance.py:12`).

The read-only provenance and assurance jobs do not receive publication secrets.
Publication uses distinct privileges:

| Consumer | Effective resource and recipient | Control and remaining assumption |
| --- | --- | --- |
| release-plz `release` | Repository writes through `GITHUB_TOKEN`; crates.io publishing through `CARGO_REGISTRY_TOKEN`, supplied to the release action. | Main push/manual dispatch, `arkworks-rs` owner guard, job permissions, checkout without persisted credentials. Action integrity and actual token scope remain administrative assumptions (`.github/workflows/release.yml:12`). |
| release-plz `release-pr` | Repository contents and PR writes through `GITHUB_TOKEN`. | Separate job permissions and serialized release-PR updates (`.github/workflows/release.yml:37`). |
| Pages deployment | Generated `target/doc`, uploaded to GitHub Pages using Pages/OIDC permissions. | `github-pages` environment and serialized deployment. Repository settings determine approvals and audience (`.github/workflows/docs.yml:11`, `.github/workflows/docs.yml:25`, `.github/workflows/docs.yml:39`). |

Repository branch protection, environment approval rules, external action
integrity and account security are not established by these workflow files.
The `status-check` job aggregates checks; administrators must make it required
for merge enforcement (`.github/workflows/pr.yml:179`).

## Assurance and its limits

| Objective | Evidence and scope |
| --- | --- |
| Memory safety | Workspace `unsafe_code = "forbid"`; nightly Miri over core unit tests with default and no-default features. Miri uses portable SHA-2/Keccak and omits megabyte stress tests, which run natively (`Cargo.toml:45`, `.github/workflows/assurance.yml:23`). |
| Parser totality and transcript binding | Structure-directed properties cover reader transitions, count prefixes, zero-progress codecs, swallowed failures, malformed strings, tag/instance binding and chunked sponge traces. The challenge-echo fixture tests transcript binding, not proof-system soundness (`spongefish/tests/property.rs:1`). |
| Extended exploration | 256 cases per property normally; 100,000 nightly, with shrunk counterexample artifacts on failure (`.github/workflows/assurance.yml:52`). |
| Release arithmetic | Workspace tests with overflow checks and debug assertions enabled under release optimization, included in the PR status anchor (`.github/workflows/pr.yml:159`). |
| Coverage | Core crate line coverage floor of 80%, initially measured at 83.3%; tests/examples and experimental crates are outside this metric (`.github/workflows/assurance.yml:72`). |
| Specification behavior | Each suite harness executes 11 of 13 records. P-256 reduction for `DecodeUint` and two Sumcheck records are outside that harness; a separate sumcheck integration test exercises its own vector. Provenance runs on every PR/main push through the reusable workflow, plus weekly (`spongefish/tests/spec_fs.rs:20`, `.github/workflows/test-vectors.yml:3`). |
| Dependency and platform compatibility | `cargo-deny`, locked builds, declared MSRV tests and WASM tests in CI (`deny.toml:1`, `.github/workflows/pr.yml:88`, `.github/workflows/pr.yml:125`). |

During setup, local Miri 0.1.0 (`66da6cae1a`, 2026-04-20) reported a Stacked
Borrows aliasing violation in `sha2 0.11.0`'s optimized ARM SHA-256 path. This is an
untriaged dependency/toolchain observation, not a validated exploitable finding.
Miri also does not support the ARM Keccak intrinsics used by this dependency
version. The portable-backend lane does not resolve or cover those paths. Native tests retain
normal backend selection but cannot establish absence of undefined behavior.

The main failure scenarios to guard against are accepting altered or incomplete
transcripts, transcript collisions from invalid codecs or reused context tags,
biased/reused randomness exposing a witness, hostile sizes exhausting verifier
resources, and compromised build inputs obtaining publication authority. These
are threat scenarios, not findings. Tests, Miri and coverage provide bounded
evidence; they do not prove cryptographic security, constant-time execution or
the safety of arbitrary downstream protocols.
