# Release Flow Experiment

This branch prototypes an automated release PR flow that only needs the default `GITHUB_TOKEN` plus a crates.io token.

## What the workflow does

The release workflow in `.github/workflows/release.yml` runs when pull requests targeting `main` are merged.

It performs these steps in order:

1. When a normal pull request is merged into `main`, the workflow checks out `main`.
2. It reruns the publish-critical gates:
   - `cargo test --workspace --all-features --locked`
   - `cargo doc --workspace --all-features --no-deps --locked` with `docsrs` warnings denied
3. It bumps the workspace minor version by editing the root `Cargo.toml`.
4. It uses `GITHUB_TOKEN` to create or update a `release/next` pull request back into `main`.
5. When that release PR is merged, the workflow reruns the same gates, publishes crates in dependency order, and creates the GitHub release and tag.

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

## GitHub token behavior

The release preparation step uses the default `GITHUB_TOKEN` to update the `release/next` branch and maintain the release PR.

No separate bot PAT is required for the workflow itself.

Enable `Settings -> Actions -> General -> Workflow permissions -> Allow GitHub Actions to create and approve pull requests` so the release PR can be created with `GITHUB_TOKEN`.

## Operational caveats

This design assumes release runs are serialized. The workflow uses a single concurrency group per branch, and repeated merges update the same `release/next` PR instead of creating a stack of release PRs.

The workflow also supports manual runs from the Actions tab. Choose `prepare` to create or refresh the release PR, or `publish` to run the publish path against the version currently on `main`.

Because the crates depend on each other at the new version, a full pre-publish package validation is not possible for the entire workspace before the first crate is released. The workflow handles that by validating and publishing each crate in dependency order instead.
