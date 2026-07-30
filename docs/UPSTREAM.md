# Oracle upstream synchronization

`mv-oci-sdk` is a curated distribution of the Oracle OCI Python SDK. It does
not track Oracle's moving `master` branch.

The former `checkout_upstream_changes.bat` workflow has been removed so there
is no moving-branch synchronization path alongside the immutable workflow.

The immutable upstream release is recorded in
`upstream/oci-python-sdk.json`, and the copied package paths are listed in
`upstream/selected-paths.txt`. The synchronization script also removes the
legacy paths in `upstream/prune-paths.txt`.

From a clean `mv-oci-sdk` worktree, run:

```text
python scripts/sync_upstream.py /path/to/oci-python-sdk
```

The supplied checkout must contain the exact recorded tag and commit. The
script refuses dirty worktrees, archives only the selected paths from that
commit, removes stale content under those paths, applies the documented Moviri
overlay, and reports the resulting added, removed, and changed files. It does
not bump arbitrary versions, build artifacts, or publish packages.

## Moviri overlay

The overlay is deliberately small:

- `src/oci/__init__.py` is replaced by
  `upstream/oci-init-overlay.py`, so only retained services are advertised and
  lazy-importable.
- `src/oci/version.py` receives the Moviri release suffix recorded in upstream
  metadata.
- `ServiceError` and `TransientServiceError` are created without a timestamp,
  and omit the timestamp field from their output, preserving Dynatrace's
  stable exception formatting.
- Circuit-breaker request monitoring keys off the configured strategy, avoiding
  the fork's previously observed unwanted warning/state path.
- URI userinfo is redacted as a whole so proxy usernames and passwords cannot
  escape through logs or exception text.

All other retained SDK source comes byte-for-byte from the recorded Oracle
commit.
