# Release Flow Experiment

This branch prototypes a `release-plz`-based release flow for the workspace.

## What the workflow does

The release workflow in `.github/workflows/release.yml` runs on pushes to `main` and uses `release-plz`.

It performs these steps in order:

1. `release-plz release-pr` creates or updates the release PR using `GITHUB_TOKEN`.
2. Merging that release PR allows `release-plz release` to publish any unpublished crates from `main`.
3. `release-plz release` also creates the git tag and GitHub release.
4. The shared workspace version is kept in sync through `version_group` configuration in [release-plz.toml](/Users/maker/Code/sigma/spongefish-mu-release/release-plz.toml).
5. This branch is configured to always bump the pre-1.0 minor version line, so `0.3.0` prepares `0.4.0`, then `0.5.0`, and so on.

## Required GitHub configuration

Add a repository secret named `CARGO_REGISTRY_TOKEN`.

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
5. Add the token as `CARGO_REGISTRY_TOKEN`.

## GitHub token behavior

`release-plz release-pr` uses the default `GITHUB_TOKEN` to open and update the release PR.

No separate bot PAT is required.

Enable `Settings -> Actions -> General -> Workflow permissions -> Allow GitHub Actions to create and approve pull requests` so release-plz can create the release PR.

## Operational caveats

This design assumes release runs are serialized. The `release-plz release-pr` job uses a single concurrency group per branch, so repeated merges update the existing release PR instead of creating a stack of PRs.

The workflow also supports manual runs from the Actions tab through `workflow_dispatch`.

The minor-bump policy is implemented through `custom_minor_increment_regex = "^"` and a shared `version_group`. This is intentionally opinionated and trades standard pre-1.0 semver behavior for predictable `0.x -> 0.(x+1)` releases.
