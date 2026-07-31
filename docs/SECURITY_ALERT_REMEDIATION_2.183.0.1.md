# Security alert remediation for 2.183.0.1

This record maps the open GitHub CodeQL and Dependabot findings imported on
2026-07-31 to the `upgrade/oci-2.183.0` branch. Static triage used commit
`283a2bfa35f93d9b00776125285055b0824b9a5e` as its initial target revision.
The repository does not contain a `SECURITY.md`; the supported boundary is the
consumer-exclusive package scope documented in
`DEVELOPMENT_SPEC_2.183.0.1_REMEDIATION.md` and `UPSTREAM.md`.

GitHub reports Dependabot findings against the default branch. Findings whose
affected dependency or path is absent from this upgrade branch remain open
until this pull request is merged and GitHub rescans `master`.

## Code scanning

| Alert | Rule | Static triage | Branch disposition |
| ---: | --- | --- | --- |
| 8 | `actions/missing-workflow-permissions` | `not_actionable`, high confidence: the finding is anchored to `master`; this branch declares `contents: read`. | Already remediated by least-privilege workflow permissions. |
| 7 | `py/insecure-default-protocol` | `not_actionable`, high confidence: the reported vendored urllib3 path is absent. | Vendored urllib3 is removed; `urllib3>=2.6.3` is external. |
| 6 | `py/insecure-protocol` | `not_actionable`, high confidence: the reported vendored urllib3 path is absent. | Vendored urllib3 is removed; `urllib3>=2.6.3` is external. |
| 5 | `py/insecure-protocol` | `not_actionable`, high confidence: the reported vendored urllib3 path is absent. | Vendored urllib3 is removed; `urllib3>=2.6.3` is external. |
| 4 | `py/weak-sensitive-data-hashing` | `not_actionable`, high confidence: the hash was part of an unused internal HTTP Digest handler with no retained SDK or consumer caller. | The unsupported handler and password-digest code are removed by a durable overlay. |
| 3 | `py/weak-sensitive-data-hashing` | `not_actionable`, high confidence: the hash was part of an unused internal HTTP Digest handler with no retained SDK or consumer caller. | The unsupported handler and password-digest code are removed by a durable overlay. |
| 2 | `py/weak-sensitive-data-hashing` | `not_actionable`, high confidence: the hash was part of an unused internal HTTP Digest handler with no retained SDK or consumer caller. | The unsupported handler and password-digest code are removed by a durable overlay. |
| 1 | `py/weak-sensitive-data-hashing` | `not_actionable`, high confidence: the hash was part of an unused internal HTTP Digest handler with no retained SDK or consumer caller. | The unsupported handler and password-digest code are removed by a durable overlay. |

The HTTP Digest removal preserves the vendored `AuthBase`, `HTTPBasicAuth`,
`HTTPProxyAuth`, and `_basic_auth_str` interfaces used by OCI signing, prepared
request URL authentication, and proxy authentication. Focused tests verify
both the absent handler and valid Basic/proxy headers.

## Dependabot vulnerabilities

| Alert | Advisory and package | Static triage | Branch disposition |
| ---: | --- | --- | --- |
| 14 | `GHSA-rpj2-4hq8-938g`, vcrpy | `not_actionable`, high confidence: vcrpy is absent from the branch manifest. | Removed with the obsolete upstream development dependency set. |
| 13 | `GHSA-6w46-j5rx-g56g` / `CVE-2025-71176`, pytest | `needs_review` rank 1, high confidence: the validation requirement admitted affected pytest versions even though normal resolution selected a patched release. | Minimum raised to `pytest>=9.0.3,<10` and covered by a package-contract test. |
| 7 | `GHSA-597g-3phw-6986` / `CVE-2026-22702`, virtualenv | `not_actionable`, high confidence: virtualenv is absent from the branch manifest. | Removed with the obsolete upstream development dependency set. |
| 6 | `GHSA-vxmw-7h4f-hqxh`, PyPI publish action | `not_actionable` for the advisory because `release/v1` currently resolves beyond the patched 1.13.0 release; the moving ref remained a quality risk. | Pinned to commit `dc37677b2e1c63e2034f94d8a5b11f265b73ba33`, referenced by the signed v1.14.2 tag. |
| 5 | `GHSA-cpwx-vrp4-4pq7` / `CVE-2025-27516`, Jinja2 | `not_actionable`, high confidence: Jinja2 is absent from the branch manifest. | Removed with the obsolete upstream documentation dependency set. |
| 4 | `GHSA-rqc4-2hc7-8c8v` / `CVE-2024-53899`, virtualenv | `not_actionable`, high confidence: virtualenv is absent from the branch manifest. | Removed with the obsolete upstream development dependency set. |
| 3 | `GHSA-q2x7-8rv6-6q7h` / `CVE-2024-56326`, Jinja2 | `not_actionable`, high confidence: Jinja2 is absent from the branch manifest. | Removed with the obsolete upstream documentation dependency set. |
| 2 | `GHSA-h75v-3vvj-5mfj` / `CVE-2024-34064`, Jinja2 | `not_actionable`, high confidence: Jinja2 is absent from the branch manifest. | Removed with the obsolete upstream documentation dependency set. |
| 1 | `GHSA-h5c8-rqwp-cp95` / `CVE-2024-22195`, Jinja2 | `not_actionable`, high confidence: Jinja2 is absent from the branch manifest. | Removed with the obsolete upstream documentation dependency set. |

No open Dependabot malware findings were returned. The final declared
requirement graph passes `pip-audit` with no known vulnerabilities.

## Remaining boundary

Default-branch alert closure depends on merging this branch and allowing
GitHub to rescan `master`. No alert is dismissed merely to make the pull
request green. Credentialed OCI runtime validation remains unavailable and is
tracked separately from static and package validation.
