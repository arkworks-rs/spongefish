# Release Flow Experiment

This branch prototypes an automatic crates.io release every time a pull request lands on `main`.

## What the workflow does

The release workflow in `.github/workflows/release.yml` runs on pushes to `main`.

It performs these steps in order:

1. Checks out `main`.
2. Runs the publish-critical gates again:
   - `cargo test --workspace --all-features --locked`
   - `cargo doc --workspace --all-features --no-deps --locked` with `docsrs` warnings denied
3. Bumps the workspace minor version by editing the root `Cargo.toml`.
4. Commits `Cargo.toml`, tags the release, dry-runs each `cargo publish` stage in dependency order, publishes crates, and pushes the commit and tag back to `main`.

## Required GitHub configuration

Add a repository secret named `CRATES_IO_TOKEN`.

Create it from a crates.io account that has publish access to all of these crates:

- `spongefish-derive`
- `spongefish`
- `spongefish-poseidon2`
- `spongefish-circuit`
- `spongefish-pow`

To create the token:

1. Sign in to [crates.io](https://crates.io).
2. Open Account Settings.
3. Create a new API token with publish scope.
4. In GitHub, open `Settings -> Secrets and variables -> Actions`.
5. Add the token as `CRATES_IO_TOKEN`.

## Branch protection requirement

The workflow pushes a release commit and tag back to `main`.

That means one of these must be true:

- GitHub Actions is allowed to bypass branch protection for `main`.
- A bot credential with push access is used instead of the default `GITHUB_TOKEN`.

If neither is true, the publish step can succeed but the final push back to `main` will fail.

## Operational caveats

This design assumes release runs are serialized. The workflow uses a single concurrency group per branch, but if merges stack up quickly you should expect to test how you want to handle queued releases.

The workflow also supports manual runs from the Actions tab. Leave `publish` unchecked to exercise the gate-and-bump path without pushing or publishing.

Because the crates depend on each other at the new version, a full pre-publish package validation is not possible for the entire workspace before the first crate is released. The workflow handles that by validating and publishing each crate in dependency order instead.
