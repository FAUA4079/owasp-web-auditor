# Phase 1: reproducible baseline and research traceability

## Scope

This phase fixes pytest collection, adds a **human-curated initial traceability matrix**, and adds structural validation tests. It does **not** introduce a vulnerability detector, import full datasets, validate the checks against benchmarks, or claim production readiness.

## Reproduce on Kali Linux (Python >= 3.11)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e . pytest
python -m pytest -q
python -m unittest discover -s tests -p 'test_*.py'
python -m auditor --help
python -m pip check
```

Store `python --version`, `python -m pip freeze` and all test logs in your own non-secret CI artifacts. Dependencies in `pyproject.toml` use ranges; reproducibility **across future package releases is not guaranteed**. For a true frozen environment, generate and review a pinned lock file in your deployment environment and repeat the test suite.

## Research and provenance

- `research/source_manifest.json`: OWASP WSTG v4.2, ASVS v5.0.0, MITRE CWE 5.0 and OWASP Top 10:2025. These are **links and release pins**, not locally downloaded datasets.
- `research/chk01_chk12_traceability.csv`: all twelve implemented CHK identifiers and corresponding code locations, existing Top 10 mapping, initial research topic and research mapping status.
- Exact ASVS requirement IDs, CWE weakness IDs and many WSTG scenario IDs remain deliberately blank pending verification against version-pinned source material. **Blank does not imply no relevant standard exists.**
- The existing Top 10 classifications are copied from the codebase, **not independently approved**. Review them during Phase 2.
- The matrix's `verified_general_guidance` means a published methodology is relevant, **not** that the scanner satisfies it or has passed ground truth validation.

## Phase 2 gates

1. Download the official machine-readable source datasets; record release asset URL, retrieval date, source license, SHA-256 digest and parser version.
2. Independently review every WSTG / ASVS / CWE mapping and distinguish methodology from conformance.
3. Build fixed, labeled secure/vulnerable fixtures and document authorization to test.
4. Run local integration tests, evaluate precision/recall **by check** and label inconclusive cases separately.
5. Recheck packaging, source archive, credentials hygiene and subprocess/CLI integration.

## Changes in Phase 1

- Renamed `test_record` to `make_record` in `tests/test_coverage.py` so pytest does not collect a test-data helper as a fixture-driven test.
- Added traceability index and structural tests. Existing production detection logic, status categories and scan behavior remain unchanged.
