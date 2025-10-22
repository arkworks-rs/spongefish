spongefish: a duplex sponge Fiat-Shamir library 🧽🐟
=========

Sponge FiSh (duplex **sponge** **Fi**at-**Sh**amir) is a permutation-agnostic Fiat-Shamir library that believes in random oracles.
It facilitates the writing of multi-round public coin protocols.
It provides a generic API for generating the verifier's random coins and the prover randomness.
The project has the following crates:

- `spongefish`: the core library, with bindings for [`group`](https://github.com/zkcrypto/group) and [`ark-ff`](https://arkworks.rs). This crate provides the basic traits for hashes and a duplex sponge API;
- `spongefish-pow`: an extension for challenges computed via grinding / proof-of-work;
- `spongefish-poseidon`: a **WORK IN PROGRESS** implementation of the [Poseidon](https://anemoi-hash.github.io/) hash function (in arkworks).
- `spongefish-anemoi`: a **WORK IN PROGRESS** implementation of the [Anemoi](https://anemoi-hash.github.io/) hash function (in arkworks);

Legacy hash functions, such as **compression functions**, are also supported via Rust's generic [`Digest`](https://docs.rs/digest/latest/digest/) API.

# Features

**Automatic transcript generation.** spongefish comes with batteries included for serializing/deserializing algebraic elements such as field/group elements in [arkworks](https://github.com/arkworks-rs/algebra) and [zkcrypto](https://github.com/zkcrypto/group). Users can build on the top of it via extension traits.

**Support custom hash function.**
To build a secure Fiat-Shamir transformation, the minimal requirement is a permutation function over some set that supports byte-encoding. It can be a `u8` representing $\mathbb{F}_{2^8}$ or any large-characteristic prime field $\mathbb{F}_p$.

**Retro-compatibility.**
We have a legacy interface for any hash function that satisfies the [`digest::Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) trait, such as [`sha2`](https://crates.io/crates/sha2) and [`blake2`](https://crates.io/crates/blake2).

- **Preprocessing**.
In recursive SNARKs, minimizing the number of hash invocations
while maintaining security is crucial. We offer tools for preprocessing the Transcript (i.e., the state of the Fiat-Shamir transformation) to achieve this goal.

- **Private randomness generation**.
It is vital to avoid providing two different challenges for the same prover message. We do our best to avoid it by tying down the prover randomness to the protocol transcript, without making the proof deterministic.

## More information
Check out the [documentation](https://arkworks.rs/spongefish/spongefish) and some [`examples/`](https://github.com/arkworks-rs/spongefish/tree/main/spongefish/examples).

## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/sigmaprotocols).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)

