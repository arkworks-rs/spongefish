# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report privately through GitHub's private vulnerability reporting:

<https://github.com/arkworks-rs/spongefish/security/advisories/new>

If you cannot use GitHub, email the maintainers listed in the `authors` field of `spongefish/Cargo.toml`.

A useful report includes:

- the affected crate(s) and commit/version + feature flags;
- the impact of the attack;
- a proof of concept or a regression test.

You should expect a response within 10 business days.
We will credit reporters in the advisory unless asked not to.
We do not operate a bug bounty and cannot offer payment.
In scope for a useful report are:

- The SHAKE128 and TurboSHAKE128 suites. These implement [`draft-irtf-cfrg-fiat-shamir`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/).
- The overwrite-mode duplex sponge.
- Encoding and serialization correctness.
- Secrecy of the private coins of the prover.
- Memory safety and panics on verification.

The experimental crates `spongefish-pow`, `spongefish-circuit`, and the elements enabled by the feature flag `yolocrypto` are to be considered out of scope.

Choosing the session identifier is the caller's responsibility: it must uniquely identify the argument system, its codecs, and the application context. A transcript collision caused by reusing one session identifier across different protocols is misuse, not a library bug.

## Supported versions

Only the **latest released version** on crates.io receives security fixes.
Users are expected to track the latest release.

This policy covers the crates published from this repository: `spongefish`,
`spongefish-derive`, `spongefish-pow`, and `spongefish-circuit`.

## Audit status

Two external reviews touch this codebase.

- **[Radically Open Security](https://www.radicallyopensecurity.com/)**, on the code as of 2024-05-28.
  Commit: `923e0fde49610dfff76c23ad0ca811442ae21e98`.
- **[OpenZeppelin](https://www.openzeppelin.com/news/interactive-sigma-proofs-and-fiat-shamir-transformation-proof-of-concept-implementation-audit)**, September 2025.
  Commit: `f427eddc973bc9ef284c342913010b57f935d71a`.

The current code-base should be considered un-audited.
