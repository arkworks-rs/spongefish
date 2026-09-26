# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0](https://github.com/arkworks-rs/spongefish/compare/v0.7.4...v0.8.0) - 2026-09-26

### Added

- *(transcript)* make prover_only infallible and add Witness combinators ([#262](https://github.com/arkworks-rs/spongefish/pull/262))
- *(pow)* proof-of-work-protected verifier messages ([#190](https://github.com/arkworks-rs/spongefish/pull/190))
- *(transcript)* add prover-only computations ([#250](https://github.com/arkworks-rs/spongefish/pull/250))

### Fixed

- *(spongefish-pow)* Blake3 sequential solve test ([#218](https://github.com/arkworks-rs/spongefish/pull/218))
- update ascon to 0.5 ([#206](https://github.com/arkworks-rs/spongefish/pull/206))

### Other

- use the imperative mood in rustdoc ([#267](https://github.com/arkworks-rs/spongefish/pull/267))
- refactor!(codecs): rename Decoding to FromUniform and NargDeserialize to FromNarg ([#263](https://github.com/arkworks-rs/spongefish/pull/263))
- rename the README grinding example to GrindingArgumentExample ([#259](https://github.com/arkworks-rs/spongefish/pull/259))
- *(codecs)* parameterise Encoding, Decoding, and Codec by the sponge Unit ([#253](https://github.com/arkworks-rs/spongefish/pull/253))
- improve circuit relation builder from the sigma-proofs api ([#251](https://github.com/arkworks-rs/spongefish/pull/251))
- Align spongefish with new Internet Draft ([#217](https://github.com/arkworks-rs/spongefish/pull/217))
- *(deps)* [**breaking**] update rand and cryptography dependencies ([#197](https://github.com/arkworks-rs/spongefish/pull/197))
