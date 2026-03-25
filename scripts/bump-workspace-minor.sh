#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_toml="$repo_root/Cargo.toml"

current_version="$(
  awk '
    $0 == "[workspace.package]" { in_workspace_package = 1; next }
    /^\[/ && $0 != "[workspace.package]" { in_workspace_package = 0 }
    in_workspace_package && $1 == "version" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' "$cargo_toml"
)"

if [[ -z "$current_version" ]]; then
  echo "failed to find workspace version in $cargo_toml" >&2
  exit 1
fi

if [[ "$current_version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-.+)?$ ]]; then
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  next_version="${major}.$((minor + 1)).0"
else
  echo "unsupported workspace version: $current_version" >&2
  exit 1
fi

perl -0pi -e 's/(\[workspace\.package\][^\[]*?version = ")([^"]+)(")/${1}'"$next_version"'${3}/s' "$cargo_toml"

for crate_path in \
  'spongefish:spongefish' \
  'spongefish-circuit:circuit' \
  'spongefish-derive:derive' \
  'spongefish-poseidon2:poseidon2'
do
  crate_name="${crate_path%%:*}"
  relative_path="${crate_path##*:}"
  perl -0pi -e 's/^'"$crate_name"' = \{[^}]*path = "'"$relative_path"'"[^}]*\}$/'"$crate_name"' = { version = "='"$next_version"'", path = "'"$relative_path"'" }/m' "$cargo_toml"
done

printf '%s\n' "$next_version"
