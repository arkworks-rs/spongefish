# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

See [GitHub releases](https://github.com/arkworks-rs/spongefish/releases) and the git history for anything older than the entry below. From the next release on, this file is maintained by [release-plz](https://release-plz.dev/).

## [Unreleased]

Summary of the work on this branch since `v0.7.4`, as recorded by `git log v0.7.4..HEAD`. This release is a substantial redesign of the public API; expect breaking changes throughout.

### Added

- `spongefish-pow::PowTranscriptExt::verifier_message_pow`, a shared proof-of-work step available on generic `Transcript` implementations and directly on `ProverState` / `VerifierState`. 
- New traits: `Argument`, used to define an interactive argument, with type parameters `Instance`, `Witness` and `Output` that define the interactive protocol. The function `Argument::run` is the interactive protocol itself, and relies on a new trait `Transcript` to declare prover / verifier messages and the verifier checks. The trait `Transcript` is implemented by `ProverState` and `VerifierState`.
- Closure-based codecs (`prover_message_as` / `verifier_message_as`, and the alphabet-generic `prover_message_with` / `verifier_message_with`).
- `NargReader`, the forward-only cursor used to read the NARG string (without relying on `std`), and `NargReader::read`, the shorthand for reading one value through it. Every read returns `VerificationError` on failure. A failed read automatically poisons the reader: all later reads fail, including empty reads, and it is never empty.
- Public `NargReader::read_with` runs custom parsers. `read` and `read_with` refuse to invoke parsers on a poisoned reader and reject `Ok` if a nested read failed. Deserializers only return errors; nested parsing uses `read` / `read_with`. Direct calls to `NargDeserialize` implementation hooks bypass this guarantee.
- `PrivateRng` is now generic over the duplex sponge.
- The `LengthPrefixed` combinator for prefix-free encoding of variable-length sequences.
- `Encoding` for tuples up to arity 8; previously only pairs and triples were covered.
- `EncodedSessionId`, the embedding of 32-byte strings into a sponge alphabet. 
- Typed session identifiers (`SessionId`), so transcript constructors cannot confuse application tags with already-derived identifiers.
- A typed, single-body API for writing a public-coin argument once and a compiler into a non-interactive argument.
- Consuming terminal-message helpers that return the prover's NARG string and make the verifier's end-of-input check mandatory.
- `VerifierState::into_narg_string`, which consumes the verifier and returns the unread rest of the NARG string, for a proof followed by data the caller parses itself.
- `spongefish-circuit`: `PermutationRelation::compile` validates a relation into a `PermutationInstance`, `PermutationInstance::is_witness_valid` checks a recorded trace against it, linear equations are written with operators on wires (`x * a + y * b + z`), over the Boolean ring for integer units (a weight is a bit mask, an equation an XOR relation), and the relation forwards the allocator's methods.

### Changed

- **Breaking:** `Encoding`, `Decoding`, and `Codec` are parameterised by the sponge [`Unit`] rather than by a slice type: `Encoding<[U]>` is now `Encoding<U>`, matching `DuplexSpongeInterface::U`. The default `Encoding<u8>` is unchanged for byte sponges; only explicit `Encoding<[u8]>` / `Decoding<[u8]>` spellings need updating.
- **Breaking:** `NargReader` and `VerifierState` are no longer `Sync`. The reader stores its state in a `Cell` so verification checks can poison it while preserving `Transcript::check(&self, ...)`.
- **Breaking:** `StdHash` is renamed `DefaultHash`, so it is not mistaken for `std::hash::Hash`.
- **Breaking:** the `VerificationResult<T>` alias is gone; the signatures spell out `Result<T, VerificationError>`.
- **Breaking:** the library aligns with the latest `draft-irtf-cfrg-fiat-shamir`: session identifiers replace `DomainSeparator`, and the SHAKE128 and TurboSHAKE128 suites are the draft's constructions.
- **Breaking:** raw `[u8]` no longer implements `Encoding`, as a bare byte string is not prefix-free. Use `LengthPrefixed`, `str`, a fixed-width array, or the closure codecs.
- **Breaking:** `PrivateRng::mix_entropy` accepts exactly one 32-byte seed.
- **Breaking:** external codecs drivers are removed, we are embracing the orphan rule. We are stopping to implement `Unit` for other libraries, as this caused a proliferation of feature flags, and down the line conflicts with versioning.
- **Breaking:** `rand` is now an optional dependency, and `getrandom`-seeded private RNG are the default for prover randomness.
- **Breaking:** `LengthPrefixed` provides a shorthand for prefix-free encodings, and replaces `Vec<T>`'s `Encoding` implementation.
- **Breaking:** deserialization reads through `&mut NargReader<'_>` instead of `&mut &[u8]`.
- **Breaking:** removed the implicit `Deref` conversion from `VerificationError` to `Result<(), VerificationError>`; construct `Err(VerificationError)` explicitly.
- **Breaking:** `VerifierState` owns its `NargReader`. A rejected prover message poisons the state rather than leaving the cursor where it was: every later read fails, `check_eof` fails, and `into_narg_string` returns an error.
- **Breaking:** A more clean approach at duplex sponge initialization. `DuplexSpongeInit` is for generic units, and `EncodedSessionId` takes care of algebraic sponges. Byte transcripts are unchanged.
- **Breaking:** the instance passed to `ProverState::{new, new_with_seed, from_parts}` and `VerifierState::new` is encoded into the sponge's alphabet (`Encoding<H::U>`) rather than into bytes. Identical for byte sponges.
- **Breaking:** `Permutation` requires `permute_mut` and provides `permute`, rather than the other way round. Every real permutation mixes the state in place, so implementations no longer have to write the by-value map as a wrapper around the in-place one.
- **Breaking:** `spongefish-circuit` is reworked after `sigma-proofs`' `LinearRelation`. `PermutationInstanceBuilder` is `PermutationRelation` and its `snapshot` is a validating `compile` returning `Result`, `LinearEquation` holds a `Sum` of `Weighted` terms, instance and witness fields are private behind slice accessors, the witness is the trace alone, and allocation methods follow `sigma-proofs` names (`allocate_var`, `allocate_vars_with`, `set_var`). Assigning a wire twice with different values is a panic instead of a silent overwrite, and the `hashbrown` and `itertools` dependencies are gone.
- `NargDeserialize` gained a provided `deserialize_array_from_narg`, which `[T; N]` delegates to. `u8` overrides it with a single bounds-checked copy, so `[u8; 32]` — the shape carrying compressed points, scalars and digests — is one fixed-size read instead of 32 element parses: 57.7ns to 1.1ns, and 122ns to 4.7ns for a derived struct of two such fields. End to end this makes verification about twice as fast (a 32-round transcript goes from 7.8µs to 4.0µs). The NARG string is byte-identical.
- **Breaking:** `spongefish-circuit` moves to Plonky3 0.7 (`p3-baby-bear`, `p3-field`), so `BabyBearUnit` wraps the 0.7 `BabyBear`.
- Updated `ascon` to 0.5, along with routine dependency updates.

### Fixed

- Failed `Transcript::check` calls permanently reject the verifier: subsequent checks, message reads, `check_eof`, and `into_narg_string` fail even if the original error is caught. A caught failure in a nested check also rejects the enclosing check.
- Reader and verifier batch methods reject empty reads after poisoning. Parsers returning `Ok` after a caught nested read failure are rejected at the reader boundary.
- Rejected zero-width elements in `LengthPrefixed`.
- More careful zeroize for the `DuplexSponge` state.
- `prover_message_as` and `prover_message_with` accept a closure that consumes the whole remaining NARG string. The pointer-identity check they used to validate the caller's cursor with rejected an empty remainder, failing verification for an otherwise valid proof.
- `spongefish-derive`: the generated code is usable from `no_std` crates, and the `Decoding` derive now single-sources the field width. Malformed input is reported as a `compile_error!` on the offending span instead of aborting the macro with a panic.
- `spongefish-pow`: guarded the difficulty parameter and the endianness of the ground nonce. Dropped an unused dependency.

### Security

- Declared a minimum supported Rust version (1.88; `spongefish-circuit` requires 1.93 for its Plonky3 dependencies) and added supply-chain (`cargo-deny`), semver, and locked-dependency checks to CI.
- Added `SECURITY.md` with a private vulnerability disclosure process.
- Forbade `unsafe` code workspace-wide.

[Unreleased]: https://github.com/arkworks-rs/spongefish/compare/v0.7.4...HEAD
