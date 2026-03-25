# spongefish: a duplex sponge Fiat–Shamir library 🧽🐟

Sponge FiSh (duplex **sponge** **Fi**at–**Sh**amir) is a permutation-agnostic Fiat–Shamir library that believes in random oracles.
It facilitates the writing of multi-round public coin protocols.
It provides a generic API for generating the verifier's random coins and the prover randomness.
The project is split into several crates:

- `spongefish`: the core library and trait implementations for arkworks/zkcrypto types together with the duplex sponge API.
- `spongefish-circuit`: constraint builders for permutation-based relations.
- `spongefish-derive`: derive macros for codecs and related traits.
- `spongefish-pow`: proof‑of‑work helpers for deriving Fiat–Shamir challenges via grinding.

Hash function can also be derived via bridges to Rust's generic [`Digest`](https://docs.rs/digest/latest/digest/) API, and [`XofReader`](https://docs.rs/digest/latest/digest/trait.XofReader.html).

## More information

Check out the [documentation](https://arkworks.rs/spongefish/) and some [`examples/`](https://github.com/arkworks-rs/spongefish/tree/main/spongefish/examples).

## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/sigmaprotocols).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
