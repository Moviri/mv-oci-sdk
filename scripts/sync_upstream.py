#!/usr/bin/env python3
"""Synchronize the curated OCI SDK payload from an immutable Oracle release."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
METADATA_PATH = REPO_ROOT / "upstream" / "oci-python-sdk.json"
MANIFEST_PATH = REPO_ROOT / "upstream" / "selected-paths.txt"
PRUNE_PATH = REPO_ROOT / "upstream" / "prune-paths.txt"
INIT_OVERLAY_PATH = REPO_ROOT / "upstream" / "oci-init-overlay.py"


def run_git(
    args: list[str],
    *,
    cwd: Path,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        text=True,
        capture_output=capture_output,
    )


def read_path_list(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def require_clean_worktree() -> None:
    status = run_git(
        ["status", "--porcelain", "--untracked-files=all"],
        cwd=REPO_ROOT,
    ).stdout
    if status:
        raise RuntimeError(
            "Refusing to synchronize a dirty worktree. Commit or stash all changes first."
        )


def verify_upstream(upstream_checkout: Path, metadata: dict[str, str]) -> None:
    if not upstream_checkout.is_dir():
        raise RuntimeError(f"Oracle checkout does not exist: {upstream_checkout}")

    expected_commit = metadata["commit"]
    tag_ref = f"refs/tags/{metadata['tag']}^{{commit}}"
    resolved_tag = run_git(
        ["rev-parse", "--verify", tag_ref],
        cwd=upstream_checkout,
    ).stdout.strip()
    if resolved_tag != expected_commit:
        raise RuntimeError(
            f"{metadata['tag']} resolved to {resolved_tag}, expected {expected_commit}"
        )

    resolved_commit = run_git(
        ["rev-parse", "--verify", f"{expected_commit}^{{commit}}"],
        cwd=upstream_checkout,
    ).stdout.strip()
    if resolved_commit != expected_commit:
        raise RuntimeError(
            f"Oracle checkout does not contain expected commit {expected_commit}"
        )


def safe_extract(archive_path: Path, destination: Path) -> None:
    destination = destination.resolve()
    with tarfile.open(archive_path, mode="r:") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if destination != target and destination not in target.parents:
                raise RuntimeError(f"Unsafe archive path: {member.name}")
            if member.issym() or member.islnk():
                raise RuntimeError(f"Links are not allowed in the upstream archive: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise RuntimeError(f"Unsupported archive member: {member.name}")

            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"Unable to read archive member: {member.name}")
            with source, target.open("wb") as destination_file:
                shutil.copyfileobj(source, destination_file)
            target.chmod(member.mode & 0o777)


def archive_selected_paths(
    upstream_checkout: Path,
    commit: str,
    selected_paths: list[str],
    destination: Path,
) -> None:
    archive_path = destination / "selected-paths.tar"
    with archive_path.open("wb") as archive_file:
        subprocess.run(
            [
                "git",
                "archive",
                "--format=tar",
                commit,
                "--",
                *selected_paths,
            ],
            cwd=upstream_checkout,
            check=True,
            stdout=archive_file,
        )
    safe_extract(archive_path, destination)
    archive_path.unlink()


def remove_path(relative_path: str) -> None:
    target = (REPO_ROOT / relative_path).resolve()
    if REPO_ROOT != target and REPO_ROOT not in target.parents:
        raise RuntimeError(f"Refusing to remove path outside repository: {relative_path}")
    if target.is_dir():
        shutil.rmtree(target)
    elif target.exists():
        target.unlink()


def copy_selected_paths(extracted_root: Path, selected_paths: list[str]) -> None:
    for relative_path in selected_paths:
        source = extracted_root / relative_path
        if not source.exists():
            raise RuntimeError(f"Selected path is absent from upstream commit: {relative_path}")

        remove_path(relative_path)
        destination = REPO_ROOT / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            shutil.copy2(source, destination)


def replace_exact(path: Path, old: str, new: str, description: str) -> None:
    content = path.read_text(encoding="utf-8")
    occurrences = content.count(old)
    if occurrences != 1:
        raise RuntimeError(
            f"Expected one {description} location in {path}, found {occurrences}"
        )
    path.write_text(content.replace(old, new), encoding="utf-8")


def apply_moviri_overlay(metadata: dict[str, str]) -> None:
    shutil.copy2(INIT_OVERLAY_PATH, REPO_ROOT / "src" / "oci" / "__init__.py")

    version_path = REPO_ROOT / "src" / "oci" / "version.py"
    replace_exact(
        version_path,
        '__version__ = "2.183.0"',
        f'__version__ = "{metadata["moviri_version"]}"',
        "upstream version",
    )

    base_client_path = REPO_ROOT / "src" / "oci" / "base_client.py"
    replace_exact(
        base_client_path,
        "        self.circuit_breaker_name = None\n",
        "",
        "legacy circuit breaker name",
    )
    replace_exact(
        base_client_path,
        "if self.circuit_breaker_name:\n",
        "if self.circuit_breaker_strategy:\n",
        "circuit breaker state check",
    )
    replace_exact(
        base_client_path,
        "self.raise_transient_service_error(request, response, service_code, message, operation_name, api_reference_link, target_service, request_endpoint, client_version, timestamp, deserialized_data)\n",
        "self.raise_transient_service_error(request, response, service_code, message, operation_name, api_reference_link, target_service, request_endpoint, client_version, None, deserialized_data)\n",
        "TransientServiceError timestamp",
    )
    replace_exact(
        base_client_path,
        "self.raise_service_error(request, response, service_code, message, operation_name, api_reference_link, target_service, request_endpoint, client_version, timestamp, deserialized_data)\n",
        "self.raise_service_error(request, response, service_code, message, operation_name, api_reference_link, target_service, request_endpoint, client_version, None, deserialized_data)\n",
        "ServiceError timestamp",
    )

    exceptions_path = REPO_ROOT / "src" / "oci" / "exceptions.py"
    replace_exact(
        exceptions_path,
        '            "timestamp": self.timestamp,\n',
        "",
        "ServiceError timestamp output",
    )

    redaction_path = REPO_ROOT / "src" / "oci" / "_log_redaction.py"
    replace_exact(
        redaction_path,
        "_SENSITIVE_LOG_PATTERNS = (\n",
        (
            "_SENSITIVE_LOG_PATTERNS = (\n"
            "    # URI userinfo can contain proxy usernames and passwords.\n"
            "    (\n"
            "        re.compile(r\"(?i)\\b([a-z][a-z0-9+.-]*://)([^/@\\s]+)@\"),\n"
            "        r\"\\1\" + REDACTED_VALUE + \"@\",\n"
            "    ),\n"
        ),
        "URI userinfo redaction overlay",
    )


def print_summary() -> None:
    status = run_git(
        ["status", "--short", "--untracked-files=all"],
        cwd=REPO_ROOT,
    ).stdout.rstrip()
    if not status:
        print("Synchronization produced no changes.")
        return

    counts = {"added": 0, "removed": 0, "changed": 0}
    for line in status.splitlines():
        code = line[:2]
        if code == "??" or "A" in code:
            counts["added"] += 1
        elif "D" in code:
            counts["removed"] += 1
        else:
            counts["changed"] += 1

    print(
        "Synchronization summary: "
        f"{counts['added']} added, {counts['removed']} removed, "
        f"{counts['changed']} changed paths"
    )
    print(status)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Synchronize selected OCI SDK paths from the exact Oracle tag recorded "
            "in upstream/oci-python-sdk.json."
        )
    )
    parser.add_argument(
        "oracle_checkout",
        type=Path,
        help="Path to a git checkout containing the recorded Oracle tag and commit.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    selected_paths = read_path_list(MANIFEST_PATH)
    prune_paths = read_path_list(PRUNE_PATH)
    upstream_checkout = args.oracle_checkout.resolve()

    require_clean_worktree()
    verify_upstream(upstream_checkout, metadata)

    with tempfile.TemporaryDirectory(prefix="mv-oci-sdk-sync-") as temp_dir:
        extracted_root = Path(temp_dir)
        archive_selected_paths(
            upstream_checkout,
            metadata["commit"],
            selected_paths,
            extracted_root,
        )
        copy_selected_paths(extracted_root, selected_paths)

    for relative_path in prune_paths:
        remove_path(relative_path)

    apply_moviri_overlay(metadata)
    print(
        f"Synchronized Oracle {metadata['tag']} ({metadata['commit']}) "
        f"as mv-oci-sdk {metadata['moviri_version']}."
    )
    print_summary()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
