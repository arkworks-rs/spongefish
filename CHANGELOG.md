# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

See [GitHub releases](https://github.com/arkworks-rs/spongefish/releases) and the git history for anything older than the entry below. From the next release on, this file is maintained by [release-plz](https://release-plz.dev/).

## [Unreleased]

Summary of the work on this branch since `v0.7.4`, as recorded by `git log v0.7.4..HEAD`. This release is a substantial redesign of the public API; expect breaking changes throughout.

### Added

- Closure-based codecs (`prover_message_as` / `verifier_message_as`, and the alphabet-generic `prover_message_with` / `verifier_message_with`).
- `NargReader`, the forward-only cursor used to read the NARG string (without relying on `std`).
- `PrivateRng` is now generic over the duplex sponge.
- The `LengthPrefixed` combinator for prefix-free encoding of variable-length sequences.
- `Encoding` for tuples up to arity 8; previously only pairs and triples were covered.
- `UnitFromBytes`, the embedding of 32-byte strings into a sponge alphabet. 
- `ProverState::from_tag_with` / `VerifierState::from_tag_with`, which implements `DeriveSessionID` from the specification.

### Changed

- **Breaking:** the library aligns with the latest `draft-irtf-cfrg-fiat-shamir`: session identifiers replace `DomainSeparator`, and the SHAKE128 and TurboSHAKE128 suites are the draft's constructions.
- **Breaking:** external codecs drivers are removed, we are embracing the orphan rule. We are stopping to implement `Unit` for other libraries, as this caused a proliferation of feature flags, and down the line conflicts with versioning.
- **Breaking:** `rand` is now an optional dependency, and `getrandom`-seeded private RNG are the default for prover randomness.
- **Breaking:** `LengthPrefixed` provides a shorthand for prefix-free encodings, and replaces `Vec<T>`'s `Encoding` implementation.
- **Breaking:** deserialization reads through `&mut NargReader<'_>` instead of `&mut &[u8]`.
- **Breaking:** A more clean approach at duplex sponge initialization. `DuplexSpongeInit` is for generic units, and `UnitFromBytes` takes care of algebraic sponges. Byte transcripts are unchanged.
- **Breaking:** the instance passed to `ProverState::{new, new_with_seed, from_parts}` and `VerifierState::new` is encoded into the sponge's alphabet (`Encoding<[H::U]>`) rather than into bytes. Identical for byte sponges.
- **Breaking:** `Permutation` requires `permute_mut` and provides `permute`, rather than the other way round. Every real permutation mixes the state in place, so implementations no longer have to write the by-value map as a wrapper around the in-place one.
- `NargDeserialize` gained a provided `deserialize_array_from_narg`, which `[T; N]` delegates to. `u8` overrides it with a single bounds-checked copy, so `[u8; 32]` — the shape carrying compressed points, scalars and digests — is one fixed-size read instead of 32 element parses: 57.7ns to 1.1ns, and 122ns to 4.7ns for a derived struct of two such fields. End to end this makes verification about twice as fast (a 32-round transcript goes from 7.8µs to 4.0µs). The NARG string is byte-identical.
- Updated `ascon` to 0.5, along with routine dependency updates.

### Fixed

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
