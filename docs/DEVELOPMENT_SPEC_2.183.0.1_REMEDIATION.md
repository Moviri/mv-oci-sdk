# Development specification: remediate the OCI SDK 2.183.0 upgrade

- Status: implementation-ready
- Prepared from review: 2026-07-30
- Target branch: `upgrade/oci-2.183.0`
- Review baseline:
  `origin/master@27828acb8845cbb6f8da95c1f71a68966d5b5e9d`
- Reviewed head: `2f58d6b357d78cf7af1ba87a30e205055f1986d0`

## Execution directive

Implement this specification on the current upgrade branch. Refresh
`origin/master` before editing and confirm that the intended diff still starts
at the merge base above. If the branch has moved, revalidate every affected
path against the new diff before carrying a finding forward.

Do not publish a package, push a branch, or open a pull request unless
explicitly requested. The implementation is complete only when the focused
regressions, complete upgrade suite, package checks, repeat-sync check, and
documentation updates described below are finished.

## Objective

Make the Oracle OCI Python SDK `2.183.0` upgrade safe to merge and release by
resolving all validated review findings while preserving the repository's
curated-service boundary and reproducible synchronization model.

The result must:

- retain Oracle tag `v2.183.0` and commit
  `765efd50b3ac1f51dff2e24ad035ff31153d5826`;
- preserve Python 3.10 through 3.13 support;
- preserve the existing curated service list;
- preserve the intentional Moviri exception-formatting, redaction, package
  initialization, versioning, and circuit-breaker behaviors;
- encode every retained-source deviation durably so a later upstream sync does
  not silently remove it; and
- prevent unvalidated or arbitrary-ref publication.

## Scope and implementation invariants

Files copied from Oracle are currently expected to remain byte-for-byte equal
to the pinned Oracle commit except for the documented Moviri overlays. A fix
that changes synchronized source such as `src/oci/base_client.py`, the vendored
Requests adapter, `TokenExchangeSigner`, or generated Database Management code
must therefore be represented by one of these durable mechanisms:

1. an explicit, exact, tested transformation in `scripts/sync_upstream.py`; or
2. a small version-controlled patch mechanism invoked by that script.

Do not make an isolated hand edit that disappears on the next sync. Every new
divergence must be listed in `docs/UPSTREAM.md`, covered by a focused test, and
included in repeat-sync idempotence validation.

Keep changes narrowly scoped. Do not regenerate unrelated services or accept
large generated diffs that are not required by this specification.

## Requirements

The eight workstreams cover all nine review findings. R4 intentionally combines
the two `TokenExchangeSigner` findings.

| Review finding | Workstream |
| --- | --- |
| Disabled circuit-breaker request crash | R1 |
| Arbitrary-ref, unvalidated publication | R8 |
| Dependency-floor regression | R2 |
| urllib3 2.x chunked-request failure | R3 |
| Missing 401 refresh for `TokenExchangeSigner` | R4 |
| Repository-root deletion through sync manifests | R6 |
| Insecure token-exchange transport and logging | R4 |
| Broken Managed MySQL composite waiter | R5 |
| Developer-local tag dependency in sync tests | R7 |

### R1 — Fix requests with circuit breaking disabled

Priority: P1, release blocker

Affected paths:

- `src/oci/base_client.py`
- `scripts/sync_upstream.py`
- `upgrade_tests/test_security_and_overlays.py`

Required behavior:

- `NoCircuitBreakerStrategy` must never be passed to
  `CircuitBreakerMonitor.get()` or have `.name` dereferenced.
- A real `CircuitBreakerStrategy` must retain the existing state-monitoring
  behavior.
- Both the `OCI_SDK_DEFAULT_CIRCUITBREAKER_ENABLED=false` path and an explicitly
  supplied `NoCircuitBreakerStrategy` must work.
- The synchronization overlay must reproduce the corrected guard.

Acceptance criteria:

- A mocked request completes without `AttributeError` when the environment
  disables circuit breaking.
- A mocked request completes when `NoCircuitBreakerStrategy` is supplied
  explicitly.
- The existing configured-strategy test continues to prove that a named
  strategy is monitored.
- Re-running synchronization preserves the fix without unrelated changes.

### R2 — Preserve the dependency safety floors from `master`

Priority: P1, release blocker

Affected paths:

- `setup.py`
- `requirements.txt`
- `pyproject.toml`
- `upgrade_tests/test_package_contract.py`

Required runtime bounds:

```text
cryptography>=46.0.5,<50.0.0
pyOpenSSL>=26.0.0,<27.0.0
```

Required build bound:

```text
wheel>=0.46.2
```

Keep the compatible upper bounds introduced by the Oracle upgrade. Align all
human-readable requirements and built distribution metadata; do not leave a
second source of truth with weaker minimums.

Acceptance criteria:

- Wheel metadata contains the required runtime bounds.
- A package-contract test fails if any of the three minimum versions is
  lowered.
- A clean wheel installation resolves without dependency conflicts.
- `pip check` and `twine check` pass.

### R3 — Restore chunked-body support with external urllib3 2.x

Priority: P1, release blocker

Affected paths:

- `src/oci/_vendor/requests/adapters.py`
- the durable sync overlay or patch mechanism
- `upgrade_tests/test_transport.py`

Required behavior:

- Remove the call to `HTTPResponse.from_httplib`, which is unavailable in
  urllib3 2.x.
- Use a supported urllib3 2.x request/response path for generator-backed
  request bodies.
- Preserve fixed-length request handling, proxy selection, timeout behavior,
  retry behavior, response ownership, connection cleanup, and Requests/OCI
  exception translation.
- Keep urllib3 external and retain the declared `urllib3>=2.6.3` requirement.
  Do not reintroduce vendored urllib3 or lower its version.

Acceptance criteria:

- A local, network-independent test sends a byte-generator body as a chunked
  request and receives a successful response without `AttributeError`.
- The receiver observes the complete payload in order.
- A fixed-length request still follows the existing non-chunked path.
- A transport failure is still surfaced using the expected Requests/OCI
  exception type.
- The focused test runs against the declared urllib3 2.x dependency.

### R4 — Complete and secure `TokenExchangeSigner`

Priority: P1 for refresh behavior; P2 for transport and logging; all parts are
required before merge

Affected paths:

- `src/oci/base_client.py`
- `src/oci/auth/signers/token_exchange_signer.py`
- the durable sync overlay or patch mechanism
- `upgrade_tests/test_security_and_overlays.py`

Required refresh behavior:

- Classify `TokenExchangeSigner` as a signer eligible for the existing
  one-time 401 refresh-and-retry behavior.
- On a 401, call `refresh_security_token()` once and retry the OCI request
  once.
- Propagate a second 401; do not create an unbounded retry loop.
- Preserve proactive token refresh based on token validity and half-life.

Required transport and logging behavior:

- Preserve the current `oci_domain_url` contract: an HTTPS domain/base URL is
  accepted and `/oauth2/v1/token` is appended exactly once. Reject `http://`
  and malformed schemes before any request is made.
- Preserve the current domain-ID compatibility form, which constructs an HTTPS
  Oracle Identity URL.
- Apply a finite connection/read timeout. Reuse the established SDK default of
  `(10, 60)` unless a documented constructor option is added for this signer.
- Never log a JWT, client secret, Basic Authorization value, access token,
  refresh token, exchanged token, or complete token-response body.
- Use `oci._log_redaction` for any structured diagnostic value that must be
  logged.

Acceptance criteria:

- The BaseClient refreshable-signer predicate recognizes
  `TokenExchangeSigner`.
- A mocked 401 followed by success performs exactly one refresh and two request
  attempts.
- Two mocked 401 responses perform one refresh and propagate the second error.
- An HTTP endpoint raises a clear validation error without calling the session.
- An HTTPS exchange passes a finite timeout to `Session.post`.
- Missing-token, malformed-response, and HTTP-error tests capture logs and
  prove that sentinel credentials and tokens are absent.
- Successful exchange and proactive refresh still work with mocked HTTPS
  responses.

### R5 — Repair the Managed MySQL composite waiter

Priority: P2, required before merge

Affected paths:

- `src/oci/database_management/managed_my_sql_databases_client.py`
- `src/oci/database_management/managed_my_sql_databases_client_composite_operations.py`
- the durable sync overlay or patch mechanism
- a focused upgrade test

Required behavior:

- `change_mysql_database_management_type_and_wait_for_state()` must call a real
  work-request operation instead of an absent method.
- Add the generated-style `GET /workRequests/{workRequestId}` operation already
  used by `DbManagementClient` to `ManagedMySqlDatabasesClient`; both clients
  use the Database Management endpoint and API base path.
- If concrete service-contract evidence contradicts that implementation, stop
  and report the evidence instead of introducing a secondary client lifecycle
  or silently changing the public composite method.
- Preserve the existing immediate-return behavior when wait states are empty
  or `opc-work-request-id` is absent.
- Preserve `CompositeOperationError` and its original partial result when
  polling fails.

Acceptance criteria:

- With wait states and a work-request ID, the composite polls a valid operation
  and returns the completed work request.
- Empty wait states return the original operation response.
- A response without the work-request header returns the original operation
  response.
- A polling failure is wrapped in `CompositeOperationError` with the original
  result in `partial_results`.
- A structural regression test verifies that every
  `self.client.<method>()` call in retained composite clients exists on the
  corresponding wrapped client.

### R6 — Make synchronization path handling fail-safe

Priority: P1, release blocker

Affected paths:

- `scripts/sync_upstream.py`
- `upgrade_tests/test_sync_workflow.py`

Required behavior:

- Prevalidate every selected and pruned manifest entry before extracting,
  deleting, copying, or otherwise mutating repository content.
- Every resolved target must be a strict descendant of `REPO_ROOT`; equality
  with `REPO_ROOT` is invalid.
- Reject empty or `.` paths, absolute paths, parent traversal, and symlink
  escapes with a clear error.
- Never delete or replace `.git`.
- A validation failure must occur before any valid earlier entry has been
  mutated.

Acceptance criteria:

- Manifests containing `.`, `..`, an absolute path, or a symlink escape fail
  before any filesystem mutation.
- Selected or pruned `.git` and `.git/**` paths are rejected before repository
  metadata is touched.
- A test where a valid entry precedes an invalid entry proves that all entries
  are validated before any partial deletion or copy occurs.
- Tests preserve sentinel repository metadata and an ignored sentinel file.
- Tests use a temporary repository root; destructive cases must never target
  the developer's working checkout.
- Valid selected and prune paths retain their current behavior.

### R7 — Make synchronization tests hermetic

Priority: P2, required before merge

Affected path:

- `upgrade_tests/test_sync_workflow.py`

Required behavior:

- Unit tests must not assume that Oracle tag `v2.183.0` exists in the Moviri
  checkout or on the Moviri `origin`.
- Refactor the tag/commit validation boundary so it can be exercised using a
  temporary synthetic upstream Git repository and tag.
- Keep the checked-in metadata assertion for the pinned Oracle repository,
  tag, commit, and Moviri version, but do not resolve the Oracle tag from the
  Moviri repository.
- Unit tests must not fetch from the network or mutate the working checkout's
  Git metadata.

Acceptance criteria:

- The complete upgrade suite passes in a fresh `--no-tags` clone.
- The synthetic fixture proves both matching and mismatched tag/commit
  behavior.
- No test fetches a remote repository.
- A real replay against a separately prepared Oracle checkout remains an
  explicit release-validation step.

### R8 — Gate publication on the validated `master` artifact

Priority: P1, release blocker

Affected paths:

- `.github/workflows/publish.yml`
- a workflow contract test under `upgrade_tests/`

Required behavior:

- Retain `workflow_dispatch` for manual publication, but allow the publish job
  only when `github.ref == 'refs/heads/master'`.
- A topic branch or arbitrary tag selected during dispatch must not reach a job
  that can access `PYPI_API_TOKEN`.
- Split validation/build from publication. The publication job must depend on
  successful validation and consume the exact artifacts produced by the
  validated build job rather than rebuilding source.
- Run the upgrade suite in a Python 3.10, 3.11, 3.12, and 3.13 validation
  matrix.
- Before publication, build the wheel and source distribution, run
  `twine check`, install the wheel in a clean environment, verify imports and
  distribution identity, and run `pip check`.
- Put the PyPI secret only on the final publish job and associate that job with
  a protected `pypi` environment.
- Use least-privilege workflow permissions.
- Do not publish while implementing or testing this requirement.

Acceptance criteria:

- Static workflow tests prove the exact `master` ref guard and job
  dependencies.
- No validation/build job can read the PyPI secret.
- Failure of any required validation prevents the publish job from running.
- The publish job downloads and publishes the previously validated artifact.
- Repository setup documentation notes that approval/protection for the
  `pypi` environment must be configured in GitHub if it is not already active.

## Documentation and version disposition

Keep `2.183.0.1` as the target version and correct
`docs/RELEASE_NOTES_2.183.0.1.md` using the final repo-local results. Do not
query or mutate a package registry and do not bump the version as part of this
implementation. If the user or repository provides evidence that `2.183.0.1`
has already been published, stop and request version direction before editing
version metadata or release notes.

Documentation changes must:

- update `docs/UPSTREAM.md` to list every new curated overlay or patch;
- correct the dependency-bound description;
- replace the current validation claims and test count with newly measured
  results;
- recompute artifact sizes rather than copying the previous values; and
- document the protected `pypi` environment requirement.

Do not rerun, remove, or rewrite the existing `python-oci-compute` and
Dynatrace validation claims unless those repositories and required environments
are explicitly supplied. Clearly distinguish those earlier external results
from the SDK checks rerun after this remediation.

Do not claim credentialed OCI validation unless it was actually performed.

## Required validation

Run local checks with every available supported interpreter. The required
completion gate is a CI matrix covering Python 3.10, 3.11, 3.12, and 3.13. If a
local development instance lacks one of those interpreters, record that fact
and hand the implementation off as pending CI rather than claiming Definition
of Done.

Minimum local checks:

```text
python -m pytest upgrade_tests -q
python -m compileall -q src/oci
python -m build
python -m twine check dist/*
python -m pip check
git diff --check
```

Also provide evidence for:

- focused regression tests for R1 through R8;
- import of every packaged module;
- installation and import from the newly built wheel in a clean environment;
- absence of the official `oci` distribution in that wheel environment;
- the declared dependency bounds in wheel metadata;
- a complete repeat sync against a separately prepared checkout of Oracle
  commit `765efd50b3ac1f51dff2e24ad035ff31153d5826`;
- no diff after the second identical sync;
- a fresh Moviri no-tags clone running the upgrade suite successfully; and
- a clean final worktree aside from the intentional implementation changes.

If dependency auditing is available, run it against the clean wheel
environment and distinguish external packages from the retained vendored
libraries. Record any unavailable credential, network, interpreter, or
platform validation explicitly rather than converting it into a pass.

Because `scripts/sync_upstream.py` refuses a dirty worktree, perform repeat-sync
validation in an isolated temporary clone containing the candidate changes.
A temporary validation-only commit inside that disposable clone is permitted.
Do not commit, stash, clean, reset, or otherwise alter the user's working tree
solely to satisfy the sync check.

The pre-existing legacy-suite collection failure caused by missing
`tests.vcr_mods` is not part of this implementation. Report it separately if
it still prevents legacy test collection.

## Non-goals

- Upgrading beyond Oracle OCI Python SDK `2.183.0`.
- Adding or removing curated OCI service packages.
- Redesigning the SDK's public API or client lifecycle.
- Replacing the retained vendored Requests layer.
- Reintroducing vendored urllib3 or PyJWT.
- Broad dependency modernization beyond the required safety floors.
- Fixing unrelated generated-code defects or pre-existing vulnerabilities.
- Repairing the unrelated `tests.vcr_mods` legacy-suite fixture problem.
- Adding credentialed OCI calls or network-dependent unit tests.
- Changing `python-oci-compute` consumer metadata in this repository.
- Publishing a package as part of development.

## Definition of done

The work is complete when:

1. every requirement and acceptance criterion above is satisfied;
2. all existing 46 upgrade tests plus the new regression tests pass;
3. the Python 3.10–3.13 CI matrix, package, wheel, and repeat-sync checks pass;
4. generated content differs from the pinned Oracle source only through
   documented, reproducible overlays;
5. release and upstream documentation reflects measured final behavior;
6. no PyPI publication occurred; and
7. the implementation handoff lists changed files, test commands and results,
   remaining external setup, and any validation that could not be performed.
