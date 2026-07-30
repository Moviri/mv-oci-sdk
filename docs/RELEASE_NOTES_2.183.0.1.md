# mv-oci-sdk 2.183.0.1

This release refreshes the curated Moviri SDK from Oracle OCI Python SDK
2.142.0 to immutable upstream tag `v2.183.0`, commit
`765efd50b3ac1f51dff2e24ad035ff31153d5826`.

## Compatibility and dependencies

- Python 3.10 or newer is required.
- urllib3 is external and constrained to `urllib3>=2.6.3`.
- PyJWT is external and constrained to `PyJWT>=2.12.0`.
- Oracle's compatible vendored Requests implementation is retained.
- `cryptography` is constrained to `>=46.0.5,<50.0.0`.
- `pyOpenSSL` is constrained to `>=26.0.0,<27.0.0`.
- The isolated build requires `wheel>=0.46.2`.
- Oracle's compatible `python-dateutil`, `pytz`, `circuitbreaker`, and `crc32c`
  bounds are retained for the Python 3.10+ line.
- Vendored urllib3 and PyJWT are removed.

The locally available primary consumer, `python-oci-compute`, declares
`python_requires=">=3.10"` and imports the eight required service packages.
Its `extension/extension.yaml` still advertises a Python 3.9 minimum; that
pre-existing mismatch must be raised to 3.10 when the consumer adopts this
release. The consumer dependency on the unrelated `jwt` distribution must
also be removed or replaced with `PyJWT`; both distributions must not be
installed together merely because they expose the same top-level module.

## Curated services

Retained service packages:

- `core`
- `database`
- `database_management`
- `database_tools`
- `dns`
- `file_storage`
- `functions`
- `identity`
- `load_balancer`
- `monitoring`
- `network_load_balancer`
- `object_storage`
- `queue`
- `work_requests`

All other Oracle service packages remain excluded. Common authentication,
pagination, retry, circuit-breaker, transport, signing, configuration, region,
and waiter code is retained through the version-controlled selected-path
manifest.

## Moviri patch disposition

| Previous fork behavior | Disposition in 2.183.0.1 |
| --- | --- |
| Suppress timestamps in `ServiceError` and `TransientServiceError` | Retained as a small tested overlay. |
| Proxy connection diagnostics | Superseded by Oracle's redacted request and transport diagnostics; the old ad-hoc prints are removed. |
| Narrow proxy password masking | Superseded by Oracle's general redaction, with a tested Moviri URI-userinfo redaction guard for proxy credentials. |
| Additional vendored HTTP adapter print | Intentionally removed because it wrote directly to stdout and duplicated structured SDK logging. |
| November 2025 circuit-breaker warning/state workaround | Retained as a tested strategy-based state check that also supports disabled circuit breaking. |
| Manual region additions | Superseded by Oracle 2.183.0 region definitions. |
| Unbounded `cryptography` and `pyOpenSSL` declarations | Replaced by explicit safety floors and compatible upper bounds. |

## Transport and security

This baseline includes Oracle's bounded `HeaderParsingError` recovery,
session-scoped OCI HTTP adapter, OpenSSL 3 FIPS guard, and sensitive-data
redaction. It no longer mutates urllib3's process-wide pool mapping and it
preserves the OCI adapter when Object Storage resizes a connection pool.

The remediation also restores generator-backed chunked requests on external
urllib3 2.x, gives `TokenExchangeSigner` the existing one-time 401 refresh
behavior, requires HTTPS with finite exchange timeouts, and prevents token
exchange credentials or response bodies from entering logs. The Managed MySQL
composite operation can now poll its Database Management work request through
a generated-style client operation.

Synchronization rejects unsafe manifest targets before any repository
mutation. Manual publication validates Python 3.10 through 3.13, builds and
checks one artifact, and permits only a protected `pypi` environment on
`refs/heads/master` to publish that already-validated artifact.

## Validation results

The remediation suite passed all 90 tests on Python 3.10.20, 3.11.15,
3.12.13, and 3.13.13.

| Check | Result |
| --- | --- |
| Focused remediations | R1 through R8 regressions passed, including circuit-breaker disabled paths, urllib3 2.x chunked transport, token exchange refresh/security, Managed MySQL polling, sync path safety, hermetic tag verification, and publication contracts. |
| Packaged imports | Every module in the built `oci` package imported successfully. |
| Reproducible synchronization | Two consecutive syncs from the recorded Oracle tag and commit produced no diff after the first replay. |
| Fresh no-tags clone | The complete 90-test upgrade suite passed from a fresh Moviri clone created without tags. |
| Source compilation | `python -m compileall -q src/oci` passed. |
| Source and wheel build | Passed with `python -m build`. |
| Distribution metadata | Both artifacts passed `twine check`. |
| Clean wheel environment | `pip check` passed; every packaged module imported from the installed `mv-oci-sdk` wheel; the official `oci` distribution was absent. |
| Dependency bounds | Wheel metadata contains `cryptography<50.0.0,>=46.0.5`, `pyOpenSSL<27.0.0,>=26.0.0`, `urllib3>=2.6.3`, and `PyJWT>=2.12.0`. |
| Dependency audit | No known vulnerabilities were reported for the installed external dependencies. The private `mv-oci-sdk` distribution was not present in the public advisory index; retained vendored libraries are listed in `upstream/vendored-dependencies.txt`. |
| Credentialed OCI smoke collection | Not run because no OCI configuration or test-tenancy credentials were available. |

Earlier external upgrade validation was not rerun during this remediation:

- `python-oci-compute` previously passed all 74 tests against the local
  2.183.0.1 wheel on Python 3.12.13.
- `dt-sdk build` previously produced a signed 13,298,137-byte extension after
  the documented Python 3.10 and PyJWT adoption changes were applied to an
  isolated consumer copy.

Artifact sizes:

| Artifact | Size |
| --- | ---: |
| `mv-oci-sdk` 2.183.0.1 wheel | 7,155,650 bytes |
| `mv-oci-sdk` 2.183.0.1 source distribution | 3,643,714 bytes |
| Installed `oci` directory, including generated bytecode | 92,286,540 bytes |
| Installed `oci` source payload, excluding generated bytecode | 46,001,657 bytes |
| Earlier signed `python-oci-compute` extension | 13,298,137 bytes |

The wheel is below the 8 MB acceptance ceiling. The signed extension has 46.8%
headroom under the current
[25 MB Dynatrace extension-package limit](https://docs.dynatrace.com/docs/ingest-from/extensions/extension-limits).

The previous `mv-oci-sdk` 2.142.0.13 wheel is 6,004,579 bytes, so the new wheel
is 1,151,071 bytes (19.17%) larger. The increase is explained by generated API
growth within the unchanged retained-service manifest, concentrated in
`database`, `database_management`, `core`, and `database_tools`; no additional
Oracle service package was added to meet the upgrade.

The checked-in `python-oci-compute` metadata still requires its separate
adoption change: replace `jwt` with `PyJWT`, pin or constrain this SDK release,
and raise the extension manifest's Python minimum from 3.9 to 3.10. Installing
the current consumer metadata without the conflicting `jwt` distribution
therefore leaves that one expected `pip check` failure even though its complete
test suite passes.

## Residual lifecycle boundary

This SDK release does not add a public lifecycle to generated service clients
and does not claim to fix the Enel client/session multiplication issue.
Client reuse or cleanup in `python-oci-compute` remains a separate change with
its own extension-topology lifecycle validation.
