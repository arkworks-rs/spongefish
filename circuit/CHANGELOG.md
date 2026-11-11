# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0](https://github.com/arkworks-rs/spongefish/compare/spongefish-circuit-v0.9.0...spongefish-circuit-v0.10.0) - 2026-11-11

### Added

- make digest an optional default-enabled dependency ([#284](https://github.com/arkworks-rs/spongefish/pull/284))
- add risc0 support

### Fixed

- [**breaking**] use shared NARG readers in parser callbacks
- make Hash duplex sponge portable across pointer widths ([#171](https://github.com/arkworks-rs/spongefish/pull/171))

### Other

- release v0.9.0
- *(pow)* [**breaking**] separate puzzle strategy from transcript execution
- *(pow)* [**breaking**] remove BLAKE3 and Keccak backends
- release v0.8.0 ([#279](https://github.com/arkworks-rs/spongefish/pull/279))
- release v0.8.0 ([#242](https://github.com/arkworks-rs/spongefish/pull/242))
- *(readme)* use sumcheck as the quickstart example ([#268](https://github.com/arkworks-rs/spongefish/pull/268))
- use the imperative mood in rustdoc ([#267](https://github.com/arkworks-rs/spongefish/pull/267))
- refactor!(codecs): rename Decoding to FromUniform and NargDeserialize to FromNarg ([#263](https://github.com/arkworks-rs/spongefish/pull/263))
- rename the README grinding example to GrindingArgumentExample ([#259](https://github.com/arkworks-rs/spongefish/pull/259))
- improve circuit relation builder from the sigma-proofs api ([#251](https://github.com/arkworks-rs/spongefish/pull/251))
- Align spongefish with new Internet Draft ([#217](https://github.com/arkworks-rs/spongefish/pull/217))
- *(circuit)* remove unused p3-field dependency ([#199](https://github.com/arkworks-rs/spongefish/pull/199))
- release v0.7.4 ([#183](https://github.com/arkworks-rs/spongefish/pull/183))
- release v0.7.3 ([#172](https://github.com/arkworks-rs/spongefish/pull/172))
- release v0.7.2 ([#167](https://github.com/arkworks-rs/spongefish/pull/167))
- release v0.7.1 ([#146](https://github.com/arkworks-rs/spongefish/pull/146))
- release v0.7.0 ([#134](https://github.com/arkworks-rs/spongefish/pull/134))
- *(circuit)* define upper-limit of wire vars.
- confgure docs.rs to show required features ([#131](https://github.com/arkworks-rs/spongefish/pull/131))
- specify that each crate should use the workspace README, except `pow` ([#129](https://github.com/arkworks-rs/spongefish/pull/129))
- Prepare for the 0.3.0 release ([#91](https://github.com/arkworks-rs/spongefish/pull/91))
- *(poseidon2)* drop poseidon crate. ([#88](https://github.com/arkworks-rs/spongefish/pull/88))
- Rework GitHub Actions CI ([#84](https://github.com/arkworks-rs/spongefish/pull/84))
- Make QueryAnswerPair public and improve intefration in the crate ([#86](https://github.com/arkworks-rs/spongefish/pull/86))
- generic linear combination support in field variables ([#83](https://github.com/arkworks-rs/spongefish/pull/83))
- Add test vectors for SHAKE-128. ([#75](https://github.com/arkworks-rs/spongefish/pull/75))
- Fix hyphen in README for Fiat–Shamir
- move tests.rs to tests/builder.rs
- add fieldvar allocator with a test example
- typos
- Major rewrite with feedback from zk devs ([#71](https://github.com/arkworks-rs/spongefish/pull/71))
- Refactor using naming conventions of the academic paper.
- small fix on docs and allow to run example ([#33](https://github.com/arkworks-rs/spongefish/pull/33))
- Update README.md
- Update README.md
- Update README.md
- Restructure the project removing dependencies.
- Update README.md
- Update README.md
- Documentation
- Fixes in the implementation of Keccak and Arthur.
- Update README.md
- Small fixes on readme and cargo.toml.
- Improve documentation.
- Create README.md

## [0.9.0](https://github.com/arkworks-rs/spongefish/compare/spongefish-circuit-v0.7.4...spongefish-circuit-v0.9.0) - 2026-11-09

### Added

- make digest an optional default-enabled dependency ([#284](https://github.com/arkworks-rs/spongefish/pull/284))

### Fixed

- [**breaking**] use shared NARG readers in parser callbacks

### Other

- *(pow)* [**breaking**] separate puzzle strategy from transcript execution
- *(pow)* [**breaking**] remove BLAKE3 and Keccak backends
- release v0.8.0 ([#279](https://github.com/arkworks-rs/spongefish/pull/279))
- release v0.8.0 ([#242](https://github.com/arkworks-rs/spongefish/pull/242))
- *(readme)* use sumcheck as the quickstart example ([#268](https://github.com/arkworks-rs/spongefish/pull/268))
- use the imperative mood in rustdoc ([#267](https://github.com/arkworks-rs/spongefish/pull/267))
- refactor!(codecs): rename Decoding to FromUniform and NargDeserialize to FromNarg ([#263](https://github.com/arkworks-rs/spongefish/pull/263))
- rename the README grinding example to GrindingArgumentExample ([#259](https://github.com/arkworks-rs/spongefish/pull/259))
- improve circuit relation builder from the sigma-proofs api ([#251](https://github.com/arkworks-rs/spongefish/pull/251))
- Align spongefish with new Internet Draft ([#217](https://github.com/arkworks-rs/spongefish/pull/217))
- *(circuit)* remove unused p3-field dependency ([#199](https://github.com/arkworks-rs/spongefish/pull/199))

## [0.8.0](https://github.com/arkworks-rs/spongefish/compare/spongefish-circuit-v0.7.4...spongefish-circuit-v0.8.0) - 2026-09-30

### Other

- *(readme)* use sumcheck as the quickstart example ([#268](https://github.com/arkworks-rs/spongefish/pull/268))
- use the imperative mood in rustdoc ([#267](https://github.com/arkworks-rs/spongefish/pull/267))
- refactor!(codecs): rename Decoding to FromUniform and NargDeserialize to FromNarg ([#263](https://github.com/arkworks-rs/spongefish/pull/263))
- rename the README grinding example to GrindingArgumentExample ([#259](https://github.com/arkworks-rs/spongefish/pull/259))
- improve circuit relation builder from the sigma-proofs api ([#251](https://github.com/arkworks-rs/spongefish/pull/251))
- Align spongefish with new Internet Draft ([#217](https://github.com/arkworks-rs/spongefish/pull/217))
- *(circuit)* remove unused p3-field dependency ([#199](https://github.com/arkworks-rs/spongefish/pull/199))
