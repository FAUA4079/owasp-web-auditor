"""Offline structural checks for the documented research-prototype release."""
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]

def test_release_metadata_and_docs():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["name"] == "owasp-web-auditor"
    assert (ROOT / "README.md").is_file()
    assert (ROOT / "docs/release-checklist.md").is_file()
    assert "research prototype" in (ROOT / "README.md").read_text().lower()

def test_ci_covers_pytest_registry_and_package_build():
    flow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "pytest -q" in flow
    assert "auditor.rules --validate" in flow
    assert "python -m build" in flow

def test_no_false_benchmark_accuracy_claim():
    readme = (ROOT / "README.md").read_text()
    assert "pending" in readme.lower()
    assert "UNEXECUTED" in readme
    assert "not** a true positive" in readme
