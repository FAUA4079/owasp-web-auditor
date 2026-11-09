# Phase 3 — Deterministic Research-Backed Rule Registry

## Scope

This phase adds an **offline, data-only, schema-validated** metadata registry for CHK01–CHK12. It does not add checks, change payloads or decide whether a vulnerability exists. Existing check functions, status semantics, network budgets and report schemas are unchanged. Only the public operator selection list now cross-checks the registry's IDs with the actual implemented public checks.

## Metadata and provenance

- `auditor/rules/metadata/CHK01.json` ... `CHK12.json`: operator-facing metadata, exact ASVS/CWE candidate IDs, limitations, applicability, mode, implementation module, and safety claims.
- `auditor/rules/schema.json`: restrictive JSON Schema; unknown attributes are rejected, and no arbitrary commands, payloads or dynamic imports are supported.
- `auditor/rules/registry.py`: loads bundled records from Python package resources, validates IDs and schema, and returns immutable records.
- Source of mappings: `research/phase2_exact_mapping.csv`, with **OWASP ASVS 5.0.0**, **MITRE CWE 5.0**, and **OWASP Top 10:2025**. WSTG 4.2 guidance is referenced in the existing Phase 2 documentation, but **this registry does not invent per-rule WSTG IDs**.
- Labeled cases in `research/fixtures/case_specifications.json` are **UNEXECUTED_SPECIFICATIONS**, *not collected benchmark observations*. Only existing tests can currently demonstrate test behavior in mocked contexts.

The phase 2 validator (`tools/validate_research_mapping.py`) checks ASVS/CWE identifier membership in the **actual downloaded official files**. Registry schema validation by itself does not re-check these external sources. It also does not prove conceptual correctness, detection accuracy, or the absence of false positives.

## Offline registry commands

```bash
python -m auditor.rules --validate
python -m auditor.rules
python -m auditor.rules --check CHK12 --json
python -m auditor --list-checks
python -m pytest -q
```

For membership validation, run from the project root and provide the ASVS 5.0.0 CSV and CWE 5.0 ZIP you previously downloaded:

```bash
python tools/validate_research_mapping.py \
  --asvs /path/to/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv \
  --cwe /path/to/cwe-5.0-cwec_latest.xml.zip
```

## Execution separation

The registry deliberately stores only metadata strings and explicitly enumerated research IDs. A security check remains implemented in the existing `auditor/checks/` or `auditor/auth/checks.py` Python code. Metadata cannot define arbitrary runtime executors or change selected URLs. Adding new checks in the future requires reviewed implementation, explicit registration, source mapping, safety review and positive/negative lab tests before enabling them.

`CHK09–CHK12` remain **AuditShop-specific authenticated assessment checks** and are not made publicly selectable by the normal `--checks` argument. `CHK07` and `CHK08` still require an explicit query parameter. `CHK12` performs the configured logout workflow and is not a read-only operation, which is reflected in its safety metadata.

## Acceptance gates

1. All bundled records validate against the restrictive schema.
2. All 12 IDs, titles, scopes, prerequisites, categories and order match the original executable registry.
3. ASVS/CWE references match the existing Phase 2 traceability mapping (including deliberate empty mappings).
4. Python wheel contains the metadata JSON and schema.
5. Existing scan, resume, authorization, and report regression tests pass unchanged.
6. External source membership, controlled lab fixture execution and scientific benchmarking remain separately required.
