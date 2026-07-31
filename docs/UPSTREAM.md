# Oracle upstream synchronization

`mv-oci-sdk` is a curated distribution of the Oracle OCI Python SDK. It does
not track Oracle's moving `master` branch.

The former `checkout_upstream_changes.bat` workflow has been removed so there
is no moving-branch synchronization path alongside the immutable workflow.

The immutable upstream release is recorded in
`upstream/oci-python-sdk.json`, and the copied package paths are listed in
`upstream/selected-paths.txt`. The synchronization script also removes the
legacy paths in `upstream/prune-paths.txt`.

The retained boundary is defined exclusively by the `python-oci-compute`
extension. Its public service packages are `core`, `file_storage`, `functions`,
`identity`, `load_balancer`, `monitoring`, `network_load_balancer`, and
`object_storage`. `dns` remains packaged as an internal dependency because the
pagination module inspects the DNS `RecordCollection` and `RRSet` models. Its
unused generated client is excluded. All other Oracle service packages remain
excluded.

From a clean `mv-oci-sdk` worktree, run:

```text
python scripts/sync_upstream.py /path/to/oci-python-sdk
```

The supplied checkout must contain the exact recorded tag and commit. The
script refuses dirty worktrees and prevalidates every selected and pruned path
before extracting or changing content. Manifest targets must be strict
repository-relative descendants; repository metadata, absolute paths, parent
traversal, and symlink escapes are rejected. After validation, the script
archives only the selected paths from the recorded commit, removes stale
content under those paths, applies the documented Moviri overlay, and reports
the resulting added, removed, and changed files. It does not bump arbitrary
versions, build artifacts, or publish packages.

## Moviri overlay

The overlay is deliberately small:

- `src/oci/__init__.py` is replaced by
  `upstream/oci-init-overlay.py`, so only retained services are advertised and
  lazy-importable.
- The retained service `__init__.py` files are replaced by the overlays in
  `upstream/service-init-overlays/`. They export only clients used by the
  extension and their model packages. Unused composite wrappers, the Functions
  Invoke client, Object Storage transfer helpers, and the standalone waiter
  are removed through `upstream/prune-paths.txt`.
- `src/oci/version.py` receives the Moviri release suffix recorded in upstream
  metadata.
- `ServiceError` and `TransientServiceError` are created without a timestamp,
  and omit the timestamp field from their output, preserving Dynatrace's
  stable exception formatting.
- `src/oci/base_client.py` uses exact transformations for the stable exception
  behavior, monitors circuit-breaker state only for a real
  `CircuitBreakerStrategy`, and classifies `TokenExchangeSigner` for the
  existing one-time 401 refresh and retry.
- URI userinfo is redacted as a whole so proxy usernames and passwords cannot
  escape through logs or exception text.
- `src/oci/auth/signers/token_exchange_signer.py` is replaced by
  `upstream/token-exchange-signer-overlay.py`. The overlay preserves token
  half-life refresh and domain-ID compatibility while requiring HTTPS domain
  URLs, normalizing the token path, applying finite connection/read timeouts,
  and keeping credentials and token responses out of logs.
- `src/oci/auth/signers/oauth_exhange_token_signer.py` receives
  `upstream/oauth-exchange-logging-overlay.patch`. The patch removes direct
  stdout diagnostics and limits structured logs to non-secret event, status,
  request ID, signer-class, and exception-type metadata.
- `src/oci/_vendor/requests/adapters.py` receives an exact transport
  transformation that uses urllib3 2.x `urlopen(..., chunked=...)` handling
  for both fixed-length and generator-backed bodies instead of the removed
  `HTTPResponse.from_httplib` API.
All other retained SDK source comes byte-for-byte from the recorded Oracle
commit.

## Publication setup

The manual publication workflow validates Python 3.10 through 3.13, builds and
checks one distribution artifact, and installs its wheel in a clean
environment before a separate publish job can run. The publish job is limited
to `refs/heads/master` and consumes that exact validated artifact.

Repository administrators must configure a protected GitHub environment named
`pypi`, add required reviewers or equivalent deployment protection, and scope
`PYPI_API_TOKEN` to that environment. Without those protections, the workflow
still enforces the `master` ref guard, but it does not provide the required
human approval gate.
