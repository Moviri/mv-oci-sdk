import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from upgrade_tests.contracts import PRUNED_SOURCE_TARGETS


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sync_upstream.py"
WHEEL_VERIFY_SCRIPT = ROOT / "scripts" / "verify_wheel_pruning.py"


def load_sync_module():
    spec = importlib.util.spec_from_file_location("sync_upstream", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_wheel_verify_module():
    spec = importlib.util.spec_from_file_location(
        "verify_wheel_pruning",
        WHEEL_VERIFY_SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def run_git(repository, *args):
    control_root = repository.parent / ".git-test-control"
    hooks_directory = control_root / "hooks"
    template_directory = control_root / "template"
    hooks_directory.mkdir(parents=True, exist_ok=True)
    template_directory.mkdir(parents=True, exist_ok=True)

    environment = os.environ.copy()
    for key in tuple(environment):
        if key == "GIT_CONFIG_COUNT" or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TEMPLATE_DIR": str(template_directory),
        }
    )

    return subprocess.run(
        [
            "git",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "tag.gpgSign=false",
            "-c",
            f"core.hooksPath={hooks_directory}",
            *args,
        ],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    ).stdout.strip()


def create_synthetic_upstream(tmp_path):
    repository = tmp_path / "oracle"
    repository.mkdir()
    run_git(repository, "init")
    run_git(repository, "config", "user.name", "Sync Test")
    run_git(repository, "config", "user.email", "sync-test@example.invalid")

    payload = repository / "payload.txt"
    payload.write_text("first\n", encoding="utf-8")
    run_git(repository, "add", "payload.txt")
    run_git(repository, "commit", "-m", "first")
    tagged_commit = run_git(repository, "rev-parse", "HEAD")
    run_git(repository, "tag", "v-test")

    payload.write_text("second\n", encoding="utf-8")
    run_git(repository, "commit", "-am", "second")
    later_commit = run_git(repository, "rev-parse", "HEAD")
    return repository, tagged_commit, later_commit


@pytest.fixture
def synthetic_upstream(tmp_path):
    return create_synthetic_upstream(tmp_path)


def test_recorded_upstream_metadata_is_exact():
    metadata = json.loads(
        (ROOT / "upstream" / "oci-python-sdk.json").read_text(encoding="utf-8")
    )

    assert metadata == {
        "repository": "https://github.com/oracle/oci-python-sdk.git",
        "tag": "v2.183.0",
        "commit": "765efd50b3ac1f51dff2e24ad035ff31153d5826",
        "moviri_version": "2.183.0.1",
    }


def test_upstream_verification_accepts_matching_synthetic_tag(synthetic_upstream):
    sync = load_sync_module()
    repository, tagged_commit, _ = synthetic_upstream

    sync.verify_upstream(
        repository,
        {"tag": "v-test", "commit": tagged_commit},
    )


def test_upstream_verification_rejects_mismatched_tag_and_commit(
    synthetic_upstream,
):
    sync = load_sync_module()
    repository, _, later_commit = synthetic_upstream

    with pytest.raises(RuntimeError, match="resolved to .* expected"):
        sync.verify_upstream(
            repository,
            {"tag": "v-test", "commit": later_commit},
        )


def test_synthetic_git_ignores_hostile_signing_hooks_and_injected_config(
    tmp_path,
    monkeypatch,
):
    hostile_hooks = tmp_path / "hostile-hooks"
    hostile_hooks.mkdir()
    hook_marker = tmp_path / "hostile-hook-ran"
    pre_commit_hook = hostile_hooks / "pre-commit"
    pre_commit_hook.write_text(
        f"#!/bin/sh\ntouch {hook_marker}\nexit 1\n",
        encoding="utf-8",
    )
    pre_commit_hook.chmod(0o755)
    hostile_global = tmp_path / "hostile-global.gitconfig"
    hostile_global.write_text(
        "[commit]\n\tgpgSign = true\n"
        "[tag]\n\tgpgSign = true\n"
        f"[core]\n\thooksPath = {hostile_hooks}\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(hostile_global))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "3")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "commit.gpgSign")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")
    monkeypatch.setenv("GIT_CONFIG_KEY_1", "tag.gpgSign")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", "true")
    monkeypatch.setenv("GIT_CONFIG_KEY_2", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_2", str(hostile_hooks))

    repository, tagged_commit, later_commit = create_synthetic_upstream(tmp_path)
    sync = load_sync_module()
    sync.verify_upstream(
        repository,
        {"tag": "v-test", "commit": tagged_commit},
    )
    with pytest.raises(RuntimeError, match="resolved to .* expected"):
        sync.verify_upstream(
            repository,
            {"tag": "v-test", "commit": later_commit},
        )

    assert not hook_marker.exists()


def test_selected_manifest_paths_exist_after_sync():
    sync = load_sync_module()
    selected_paths = sync.read_path_list(ROOT / "upstream" / "selected-paths.txt")
    prune_paths = sync.read_path_list(ROOT / "upstream" / "prune-paths.txt")

    assert selected_paths
    assert len(prune_paths) == 23
    assert set(prune_paths) == PRUNED_SOURCE_TARGETS
    assert all((ROOT / relative_path).exists() for relative_path in selected_paths)
    assert all(not (ROOT / relative_path).exists() for relative_path in prune_paths)
    assert "src/oci/_vendor/urllib3" not in selected_paths
    assert "src/oci/_vendor/jwt" not in selected_paths
    selected_package_directories = {
        path.removeprefix("src/oci/")
        for path in selected_paths
        if path.startswith("src/oci/")
        and "/" not in path.removeprefix("src/oci/")
        and "." not in path.removeprefix("src/oci/")
    }
    assert selected_package_directories == {
        "_vendor",
        "auth",
        "circuit_breaker",
        "core",
        "dns",
        "file_storage",
        "functions",
        "identity",
        "load_balancer",
        "monitoring",
        "network_load_balancer",
        "object_storage",
        "pagination",
        "retry",
    }
    for service in (
        "database",
        "database_management",
        "database_tools",
        "queue",
        "work_requests",
    ):
        path = f"src/oci/{service}"
        assert path not in selected_paths
        assert path in prune_paths


def test_wheel_prune_verifier_checks_every_manifest_target(tmp_path):
    verifier = load_wheel_verify_module()
    wheel = tmp_path / "distribution.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("oci/__init__.py", "")

    verified = verifier.verify_wheel(wheel, tuple(sorted(PRUNED_SOURCE_TARGETS)))

    assert verified == 23


def test_wheel_prune_verifier_rejects_nested_pruned_content(tmp_path):
    verifier = load_wheel_verify_module()
    wheel = tmp_path / "distribution.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("oci/object_storage/transfer/upload_manager.py", "")

    with pytest.raises(RuntimeError, match="src/oci/object_storage/transfer"):
        verifier.verify_wheel(wheel, tuple(sorted(PRUNED_SOURCE_TARGETS)))


def test_workflow_has_no_implicit_moving_branch_default():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "oracle_checkout" in result.stderr
    assert "master" not in SCRIPT.read_text(encoding="utf-8")
    assert not (ROOT / "checkout_upstream_changes.bat").exists()


def test_dirty_worktree_is_refused(monkeypatch):
    sync = load_sync_module()
    monkeypatch.setattr(
        sync,
        "run_git",
        MockRunGit(" M src/oci/base_client.py\n"),
    )

    with pytest.raises(RuntimeError, match="dirty worktree"):
        sync.require_clean_worktree()


class MockRunGit:
    def __init__(self, stdout):
        self.stdout = stdout

    def __call__(self, *args, **kwargs):
        return SimpleNamespace(stdout=self.stdout)


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "",
        ".",
        "..",
        "../outside",
        "/tmp/outside",
        "C:/outside",
        ".git",
        ".git/config",
    ],
)
def test_manifest_paths_reject_unsafe_targets(tmp_path, unsafe_path):
    sync = load_sync_module()
    repository = tmp_path / "repository"
    repository.mkdir()

    with pytest.raises(RuntimeError, match="Manifest path"):
        sync.resolve_manifest_target(unsafe_path, repo_root=repository)


def test_manifest_paths_reject_symlink_escape(tmp_path):
    sync = load_sync_module()
    repository = tmp_path / "repository"
    outside = tmp_path / "outside"
    repository.mkdir()
    outside.mkdir()
    (repository / "escape").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="escapes the repository"):
        sync.resolve_manifest_target(
            "escape/payload",
            repo_root=repository,
        )


def test_manifest_paths_reject_symlink_into_git_metadata(tmp_path):
    sync = load_sync_module()
    repository = tmp_path / "repository"
    git_metadata = repository / ".git"
    git_metadata.mkdir(parents=True)
    (repository / "metadata").symlink_to(git_metadata, target_is_directory=True)

    with pytest.raises(RuntimeError, match="repository metadata"):
        sync.resolve_manifest_target(
            "metadata/config",
            repo_root=repository,
        )


def test_selected_entries_are_all_validated_before_copy(tmp_path):
    sync = load_sync_module()
    repository, extracted, sentinels = prepare_sync_roots(tmp_path)

    with pytest.raises(RuntimeError, match="Manifest path"):
        sync.apply_sync_payload(
            extracted,
            ["src/oci/valid", ".."],
            [],
            repo_root=repository,
        )

    assert_sync_sentinels_unchanged(repository, sentinels)


@pytest.mark.parametrize(
    "missing_literal",
    (
        ":(exclude)src/oci/missing",
        ":(glob)src/oci/missing",
        "src/oci/missing*",
        "src/oci/missing?",
        "src/oci/missing[abc]",
    ),
)
def test_all_selected_sources_are_preflighted_before_mutation(
    tmp_path,
    missing_literal,
):
    sync = load_sync_module()
    repository, extracted, sentinels = prepare_sync_roots(tmp_path)

    with pytest.raises(RuntimeError, match="absent from upstream commit"):
        sync.apply_sync_payload(
            extracted,
            ["src/oci/valid", missing_literal],
            [],
            repo_root=repository,
        )

    assert_sync_sentinels_unchanged(repository, sentinels)


def test_prune_entries_are_all_validated_before_mutation(tmp_path):
    sync = load_sync_module()
    repository, extracted, sentinels = prepare_sync_roots(tmp_path)

    with pytest.raises(RuntimeError, match="repository metadata"):
        sync.apply_sync_payload(
            extracted,
            ["src/oci/valid"],
            ["ignored-sentinel.txt", ".git/config"],
            repo_root=repository,
        )

    assert_sync_sentinels_unchanged(repository, sentinels)


def prepare_sync_roots(tmp_path):
    repository = tmp_path / "repository"
    extracted = tmp_path / "extracted"
    (repository / ".git").mkdir(parents=True)
    (repository / "src" / "oci" / "valid").mkdir(parents=True)
    (extracted / "src" / "oci" / "valid").mkdir(parents=True)

    sentinels = {
        ".git/config": "repository metadata\n",
        ".gitignore": "ignored-sentinel.txt\n",
        "ignored-sentinel.txt": "ignored data\n",
        "src/oci/valid/payload.txt": "old payload\n",
    }
    for relative_path, value in sentinels.items():
        target = repository / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8")
    (extracted / "src" / "oci" / "valid" / "payload.txt").write_text(
        "new payload\n",
        encoding="utf-8",
    )
    return repository, extracted, sentinels


def assert_sync_sentinels_unchanged(repository, sentinels):
    for relative_path, value in sentinels.items():
        assert (repository / relative_path).read_text(encoding="utf-8") == value


def test_valid_selected_and_prune_paths_preserve_behavior(tmp_path):
    sync = load_sync_module()
    repository, extracted, _ = prepare_sync_roots(tmp_path)
    stale = repository / "src" / "oci" / "stale"
    stale.mkdir()
    (stale / "old.txt").write_text("stale\n", encoding="utf-8")

    sync.apply_sync_payload(
        extracted,
        ["src/oci/valid"],
        ["src/oci/stale"],
        repo_root=repository,
    )

    assert (
        repository / "src" / "oci" / "valid" / "payload.txt"
    ).read_text(encoding="utf-8") == "new payload\n"
    assert not stale.exists()
    assert (repository / ".git" / "config").exists()


def test_archive_extraction_rejects_links(tmp_path):
    sync = load_sync_module()
    archive_path = tmp_path / "unsafe.tar"
    with tarfile.open(archive_path, "w") as archive:
        link = tarfile.TarInfo("src/oci/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

    with pytest.raises(RuntimeError, match="Links are not allowed"):
        sync.safe_extract(archive_path, tmp_path / "output")


def test_archive_treats_magic_looking_manifest_entries_as_literal_paths(tmp_path):
    sync = load_sync_module()
    repository = tmp_path / "literal-upstream"
    repository.mkdir()
    run_git(repository, "init")
    run_git(repository, "config", "user.name", "Sync Test")
    run_git(repository, "config", "user.email", "sync-test@example.invalid")
    literal_paths = (
        ":(exclude)payload.txt",
        ":(glob)payload.txt",
        "literal*name.txt",
        "literal?name.txt",
        "literal[abc].txt",
    )
    for index, relative_path in enumerate(literal_paths):
        (repository / relative_path).write_text(
            f"literal-{index}\n",
            encoding="utf-8",
        )
    (repository / "literalXname.txt").write_text("must-not-match\n", encoding="utf-8")
    run_git(repository, "add", "--", ".")
    run_git(repository, "commit", "-m", "literal paths")
    commit = run_git(repository, "rev-parse", "HEAD")
    extracted = tmp_path / "extracted-literals"
    extracted.mkdir()

    sync.archive_selected_paths(
        repository,
        commit,
        list(literal_paths),
        extracted,
    )

    for index, relative_path in enumerate(literal_paths):
        assert (extracted / relative_path).read_text(encoding="utf-8") == f"literal-{index}\n"
    assert not (extracted / "literalXname.txt").exists()
