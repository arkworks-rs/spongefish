# Threat model

See [SECURITY.md](../SECURITY.md) for reporting scope, supported versions, and audit status.
This document describes the intended guarantees of the library and their implementation boundaries.
The current code has not been externally audited.

## Architecture

Spongefish transforms public-coin interactive arguments into non-interactive arguments.
Big-endian targets are explicitly rejected. Embedded targets are supported: the crate is `no_std` but requires an allocator.

An application supplies an `Argument` implementation, a public instance, and an application tag.
The prover also supplies its witness.
`Narg` compiles the interactive argument into a non-interactive one: it derives a session identifier,
initializes the transcript with that identifier and the encoded instance, runs the argument, and
produces a NARG byte string. Verification runs the same argument without the witness and checks that
the complete string was consumed.
The low-level `ProverState` and `VerifierState` interfaces expose each operation separately.

## Security claims and their limits

For an `Argument` implementation that is state-restoration sound, `Narg::verify` accepts only NARG strings for which the statement holds. This claim holds in the random oracle model.
Diagonalization attacks on the Fiat-Shamir transformation ([KRS25], [Fen26]) are outside the protections of this crate, which cannot detect them. Applications that need such protection must argue the security of their construction separately.

If the `Argument` is zero-knowledge, the NARG string resulting from `Narg::prove` leaks no information about the witness.

The overwrite-mode Keccak/Ascon constructions are to be considered interchangeable with the draft's SHAKE/TurboSHAKE suites.

[KRS25]: https://eprint.iacr.org/2025/118 "Khovratovich, Rothblum, Soukhanov. How to Prove False Statements: Practical Attacks on Fiat-Shamir."
[Fen26]: https://eprint.iacr.org/2026/1838 "Fenzi. How to prove more false statements: Fiat-Shamir limitations on (generated) R1CS."

The workspace forbids unsafe code. Miri runs over the core unit tests with default and no-default features. Workspace tests run with overflow checks and debug assertions enabled under release optimization. Property tests written with `proptest` cover reader transitions, count prefixes, zero-progress codecs, swallowed failures, malformed strings, tag/instance binding and chunked sponge traces.

Specification conformance and test-vector provenance are checked automatically in CI. Dependency and platform compatibility are covered by `cargo-deny`, locked builds, declared MSRV tests and WASM tests in CI.

## Attacker capabilities and trust boundaries

An application may let an adversary choose instance contents or request sizes. Submitting a NARG string does not give the adversary code execution, or access to the prover's RNG state or the witness unless explicitly sent.
The caller has the responsibility to check the instance sizes and validity. In particular, the prover will NOT check that the witness is valid for the given instance.

For conforming codecs, verification of every NARG string should terminate with either acceptance or `VerificationError`, never a panic.

### NARG string

A malicious prover can provide truncated, extended or modified NARG strings. `NargReader` uses checked reads; the first failure poisons the reader, and every subsequent read is rejected without invoking the decoder. Custom deserializers provided by the implementer must reject invalid values and noncanonical encodings, check lengths, and terminate without panicking.

### Codecs

`Encoding` must be injective and prefix-free; `Decoding` must produce a uniform, or negligibly biased, distribution from a sufficiently wide input. Derive fields marked `skip` are intentionally not bound by the transcript.

The high-level byte transcript uses `prover_message_as`, which absorbs the actual consumed bytes and rejects swallowed read failures. The generic low-level `prover_message` and `prover_message_with` paths re-encode the parsed value: their encodings must match the prover's absorption map, including for non-byte alphabets.
Trait implementations do not prove injectivity, prefix-freeness, negligible decoding bias, adequate sponge capacity, or cryptographic security. Custom codecs and backends are trusted code.

### Verification

`Narg::verify` runs the argument, which deserializes and checks each message, and then checks EOF. NARG strings that do not conform to the codecs in use are rejected.

An argument implementation must check all of its verification equations; parsing success is not proof acceptance. `Argument` must be stateless; the high-level entry points enforce this property. That check does not prove the argument sound or zero-knowledge. Low-level callers must invoke `check_eof` or otherwise reject trailing bytes.

### Session identifier

The transformation absorbs the session identifier and the encoded instance into the transcript automatically. The choice of the session identifier (or of the tag it is derived from) and of the instance encoding is the caller's responsibility. The caller must update the session identifier with any change to the argument, its codecs, the suite, or the application context.

### Prover randomness

A 32-byte seed, drawn from OS entropy by default, is expanded into the prover's private random-number generator.
The entropy source is outside this library's control. Deterministic constructors are for tests only; seed reuse can destroy privacy.

## Out-of-scope surfaces

The experimental `spongefish-circuit` and `spongefish-pow` crates and the `yolocrypto` feature flag remain outside SECURITY.md's reporting scope.

## Spec compliance

The provenance checker reads the two suite vector files under `spongefish/tests/spec/vectors`, checks their SHA-256 values, and downloads their counterparts from `raw.githubusercontent.com/mmaker/draft-irtf-cfrg-sigma-protocols` at the full commit recorded in `spongefish/tests/spec/provenance.json`, under `poc/vectors`. Missing files, download failures and byte differences fail the check; no neighboring checkout is required. The repository and filename set are restricted by the checker.
