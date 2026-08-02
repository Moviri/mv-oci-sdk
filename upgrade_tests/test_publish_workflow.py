from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"


def workflow_content(path):
    return path.read_text(encoding="utf-8")


def test_validation_workflow_runs_automatically_without_publish_capability():
    workflow = workflow_content(VALIDATE_WORKFLOW)
    prefix = workflow.split("\njobs:\n", 1)[0]

    assert "\n  pull_request:\n" in prefix
    assert "\n  push:\n    branches:\n      - master\n" in prefix
    assert "\n  workflow_call:\n" in prefix
    assert "\npermissions:\n  contents: read\n" in prefix
    assert "environment: pypi" not in workflow
    assert "PYPI_API_TOKEN" not in workflow
    assert "gh-action-pypi-publish" not in workflow


def test_shared_validation_matrix_covers_every_supported_python():
    workflow = workflow_content(VALIDATE_WORKFLOW)
    validate = workflow.split("\n  validate:\n", 1)[1].split("\n  build:\n", 1)[0]

    assert 'python-version: ["3.10", "3.11", "3.12", "3.13", "3.14"]' in validate
    assert "python -m pytest upgrade_tests -q" in validate
    assert (
        "python -m compileall -q src/oci scripts/sync_upstream.py "
        "scripts/verify_wheel_pruning.py"
    ) in validate
    assert "python -m pip check" in validate


def test_shared_build_verifies_and_uploads_one_named_artifact():
    workflow = workflow_content(VALIDATE_WORKFLOW)
    build = workflow.split("\n  build:\n", 1)[1]

    assert "needs: validate" in build
    assert "python -m build" in build
    assert "python -m twine check dist/*" in build
    assert "python scripts/verify_wheel_pruning.py dist/*.whl" in build
    assert "python -m pip install dist/*.whl" in build
    assert 'importlib.metadata.version("mv-oci-sdk")' in build
    assert 'importlib.metadata.version("oci")' in build
    assert "python -m pip check" in build
    assert "uses: actions/upload-artifact@v4" in build
    assert "name: python-distributions" in build


def test_publish_workflow_is_manual_only_and_reuses_validation():
    workflow = workflow_content(PUBLISH_WORKFLOW)
    prefix, jobs = workflow.split("\njobs:\n", 1)
    validation, publish = jobs.split("\n  publish:\n", 1)

    assert "\n  workflow_dispatch:\n" in prefix
    assert "pull_request" not in prefix
    assert "\n  push:\n" not in prefix
    assert "\npermissions:\n  contents: read\n" in prefix
    assert "uses: ./.github/workflows/validate.yml" in validation
    assert "python -m pytest" not in validation
    assert "python -m build" not in validation
    assert "PYPI_API_TOKEN" not in validation
    assert "environment: pypi" not in validation
    assert "if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/master'" in publish
    assert "needs: validation" in publish


def test_publish_secret_is_confined_to_guarded_publish_job():
    workflow = workflow_content(PUBLISH_WORKFLOW)
    prefix, jobs = workflow.split("\njobs:\n", 1)
    validation, publish = jobs.split("\n  publish:\n", 1)

    assert "environment: pypi" in publish
    assert "uses: actions/download-artifact@v4" in publish
    assert "name: python-distributions" in publish
    assert "path: dist" in publish
    assert (
        "uses: pypa/gh-action-pypi-publish@"
        "dc37677b2e1c63e2034f94d8a5b11f265b73ba33 # v1.14.2"
        in publish
    )
    assert "packages-dir: dist/" in publish
    assert "password: ${{ secrets.PYPI_API_TOKEN }}" in publish
    assert workflow.count("PYPI_API_TOKEN") == 1
    assert "PYPI_API_TOKEN" not in prefix
    assert "PYPI_API_TOKEN" not in validation
