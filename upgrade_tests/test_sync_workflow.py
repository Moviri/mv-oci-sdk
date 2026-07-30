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


def test_recorded_tag_and_commit_are_exact_and_present():
    metadata = json.loads(
        (ROOT / "upstream" / "oci-python-sdk.json").read_text(encoding="utf-8")
    )
    resolved = subprocess.run(
        ["git", "rev-parse", f"{metadata['tag']}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    assert metadata == {
        "repository": "https://github.com/oracle/oci-python-sdk.git",
        "tag": "v2.183.0",
        "commit": "765efd50b3ac1f51dff2e24ad035ff31153d5826",
        "moviri_version": "2.183.0.1",
    }
    assert resolved == metadata["commit"]


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
