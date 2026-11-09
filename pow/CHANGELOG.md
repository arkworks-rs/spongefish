# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0](https://github.com/arkworks-rs/spongefish/compare/spongefish-pow-v0.7.4...spongefish-pow-v0.9.0) - 2026-11-09

### Added

- *(pow)* [**breaking**] integrate fused grinding with the verifier message oracle
- *(transcript)* make prover_only infallible and add Witness combinators ([#262](https://github.com/arkworks-rs/spongefish/pull/262))
- *(pow)* proof-of-work-protected verifier messages ([#190](https://github.com/arkworks-rs/spongefish/pull/190))

### Fixed

- [**breaking**] use shared NARG readers in parser callbacks ([#312](https://github.com/arkworks-rs/spongefish/pull/312))
- [**breaking**] use shared NARG readers in parser callbacks
- *(pow)* harden fused checks and simplify integration
- *(spongefish-pow)* Blake3 sequential solve test ([#218](https://github.com/arkworks-rs/spongefish/pull/218))

### Other

- *(pow)* clarify fused transcript proof of work
- *(pow)* tighten the transcript-sponge PoW documentation
- *(pow)* remove redundant clone in sequential fallback
- *(pow)* [**breaking**] separate puzzle strategy from transcript execution
- *(pow)* [**breaking**] remove BLAKE3 and Keccak backends
- *(pow)* clarify Blake3PoW nonce verification ([#298](https://github.com/arkworks-rs/spongefish/pull/298))
- release v0.8.0 ([#279](https://github.com/arkworks-rs/spongefish/pull/279))
- release v0.8.0 ([#242](https://github.com/arkworks-rs/spongefish/pull/242))
- [**breaking**] gate ProverState::from and VerifierState::from_parts behind yolocrypto ([#271](https://github.com/arkworks-rs/spongefish/pull/271))
- use the imperative mood in rustdoc ([#267](https://github.com/arkworks-rs/spongefish/pull/267))
- refactor!(codecs): rename Decoding to FromUniform and NargDeserialize to FromNarg ([#263](https://github.com/arkworks-rs/spongefish/pull/263))
- Align spongefish with new Internet Draft ([#217](https://github.com/arkworks-rs/spongefish/pull/217))

## [0.8.0](https://github.com/arkworks-rs/spongefish/compare/spongefish-pow-v0.7.4...spongefish-pow-v0.8.0) - 2026-09-30

### Added

- *(transcript)* make prover_only infallible and add Witness combinators ([#262](https://github.com/arkworks-rs/spongefish/pull/262))
- *(pow)* proof-of-work-protected verifier messages ([#190](https://github.com/arkworks-rs/spongefish/pull/190))

### Fixed

- *(spongefish-pow)* Blake3 sequential solve test ([#218](https://github.com/arkworks-rs/spongefish/pull/218))

### Other

- [**breaking**] gate ProverState::from and VerifierState::from_parts behind yolocrypto ([#271](https://github.com/arkworks-rs/spongefish/pull/271))
- use the imperative mood in rustdoc ([#267](https://github.com/arkworks-rs/spongefish/pull/267))
- refactor!(codecs): rename Decoding to FromUniform and NargDeserialize to FromNarg ([#263](https://github.com/arkworks-rs/spongefish/pull/263))
- Align spongefish with new Internet Draft ([#217](https://github.com/arkworks-rs/spongefish/pull/217))
