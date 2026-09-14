# Vector provenance

`provenance.json` records the specification repository, immutable commit, and
SHA-256 of every vendored suite vector file. Run:

```sh
python3 scripts/check-vector-provenance.py
```

The command runs from any directory and requires network access. Missing files,
download failures, checksum mismatches, and differences from the recorded upstream
revision fail the check. Every PR and main-branch push runs it through the PR
workflow's required-status anchor; a weekly run checks it independently.

When adopting a new specification revision, update the vendored files, commit ID,
and digests together, and review the vector diff. Upstream branch movement alone
does not change the vectors this version promises to implement. The Rust tests
exercise the supported records; provenance establishes their origin, not the
correctness or completeness of the specification.
