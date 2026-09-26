# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0](https://github.com/arkworks-rs/spongefish/compare/spongefish-pow-v0.7.4...spongefish-pow-v0.8.0) - 2026-09-26

### Added

- *(transcript)* make prover_only infallible and add Witness combinators ([#262](https://github.com/arkworks-rs/spongefish/pull/262))
- *(pow)* proof-of-work-protected verifier messages ([#190](https://github.com/arkworks-rs/spongefish/pull/190))

### Fixed

- *(spongefish-pow)* Blake3 sequential solve test ([#218](https://github.com/arkworks-rs/spongefish/pull/218))

### Other

- use the imperative mood in rustdoc ([#267](https://github.com/arkworks-rs/spongefish/pull/267))
- refactor!(codecs): rename Decoding to FromUniform and NargDeserialize to FromNarg ([#263](https://github.com/arkworks-rs/spongefish/pull/263))
- Align spongefish with new Internet Draft ([#217](https://github.com/arkworks-rs/spongefish/pull/217))
