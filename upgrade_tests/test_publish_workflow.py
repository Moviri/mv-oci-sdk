from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"


def workflow_sections():
    content = WORKFLOW.read_text(encoding="utf-8")
    prefix, jobs = content.split("\njobs:\n", 1)
    validate, remainder = jobs.split("\n  build:\n", 1)
    build, publish = remainder.split("\n  publish:\n", 1)
    return prefix, validate, build, publish


def test_publish_workflow_uses_least_privilege_manual_dispatch():
    prefix, _, _, _ = workflow_sections()

    assert "\n  workflow_dispatch:\n" in prefix
    assert "\npermissions:\n  contents: read\n" in prefix


def test_validation_matrix_covers_every_supported_python():
    _, validate, _, _ = workflow_sections()

    assert 'python-version: ["3.10", "3.11", "3.12", "3.13"]' in validate
    assert "python -m pytest upgrade_tests -q" in validate
    assert "python -m compileall -q src/oci" in validate
    assert "python -m pip check" in validate
    assert "PYPI_API_TOKEN" not in validate


def test_build_verifies_and_uploads_one_named_artifact():
    _, _, build, _ = workflow_sections()

    assert "needs: validate" in build
    assert "python -m build" in build
    assert "python -m twine check dist/*" in build
    assert "python -m pip install dist/*.whl" in build
    assert 'importlib.metadata.version("mv-oci-sdk")' in build
    assert 'importlib.metadata.version("oci")' in build
    assert "python -m pip check" in build
    assert "uses: actions/upload-artifact@v4" in build
    assert "name: python-distributions" in build
    assert "PYPI_API_TOKEN" not in build


def test_publish_is_master_only_and_consumes_validated_artifact():
    _, _, _, publish = workflow_sections()

    assert "if: github.ref == 'refs/heads/master'" in publish
    assert "needs: [validate, build]" in publish
    assert "environment: pypi" in publish
    assert "uses: actions/download-artifact@v4" in publish
    assert "name: python-distributions" in publish
    assert "path: dist" in publish
    assert "uses: pypa/gh-action-pypi-publish@release/v1" in publish
    assert "packages-dir: dist/" in publish
    assert "password: ${{ secrets.PYPI_API_TOKEN }}" in publish
    assert "actions/checkout" not in publish
    assert "python -m build" not in publish
