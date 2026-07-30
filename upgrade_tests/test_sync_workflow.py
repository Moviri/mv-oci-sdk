import importlib.util
import json
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sync_upstream.py"


def load_sync_module():
    spec = importlib.util.spec_from_file_location("sync_upstream", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def run_git(repository, *args):
    return subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def synthetic_upstream(tmp_path):
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


def test_selected_manifest_paths_exist_after_sync():
    sync = load_sync_module()
    selected_paths = sync.read_path_list(ROOT / "upstream" / "selected-paths.txt")

    assert selected_paths
    assert all((ROOT / relative_path).exists() for relative_path in selected_paths)
    assert "src/oci/_vendor/urllib3" not in selected_paths
    assert "src/oci/_vendor/jwt" not in selected_paths


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
