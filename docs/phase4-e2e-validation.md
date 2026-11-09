# Phase 4 extension: localhost end-to-end validation

This extension tests the **real CLI** via subprocess and a real TCP loopback HTTP server. No `httpx.MockTransport` is used in the new E2E runner, unlike Phase 4's initial fixture evaluation.

## Execute

```bash
python -m pip install -e . pytest
python tools/phase4_e2e.py
python -m pytest -q
python -m auditor.rules --validate
```

The E2E script writes `research/phase4_e2e/e2e_results.json` and `e2e_report.md` with observed statuses, request counts, test JSON hashes, schema and integrity assertions. The `test_phase4_e2e.py` regression test repeats these scenarios.

## Localhost cases

1. Hardened HTML response: CSP `frame-ancestors`, `nosniff`, protected cookie.
2. Missing security headers: missing `nosniff` and framing policy, weaker cookie attributes.
3. Python traceback text with a controlled secret marker; ensures CHK05 reports a preliminary indicator and redaction/integrity audit passes.
4. Autoindex-like directory structure with `ul` and local child link.
5. Harmless marker reflection in an explicitly configured `q` parameter.

Expected statuses were chosen *before* running the suite and are transparent in `tools/phase4_e2e.py`. All HTTP servers bind to `127.0.0.1` with automatically allocated ports. The scanner is not allowed to follow discovered links (`--no-crawl`). Separate client subprocesses use configured check allowlists. No state-changing requests are sent.

## Integrity/AI

Full run outputs are schema-checked using `load_report_data`; `audit_run` verifies request ledger and evidence hashes. For each scenario, the suite tampers with a **copy** of evidence and checks that the integrity audit catches it. The existing CLI automatically attempts optional AI reporting. The test directs it to an unavailable local port so **no generated AI text is used for expectations, classifications or scoring**.

## Scope and limitations

This is a **first-party** holdout set written for this repository and separate from Phase 4's mock scenarios. It is **not** independent third-party ground-truth evaluation and cannot demonstrate external accuracy. It tests observable statuses, not successful exploitation. CHK01 (HTTP-to-HTTPS), CHK08 (exceptional numeric input), and CHK09-CHK12 authenticated workflow remain to be exercised via complete external-process CLI E2E tests. Existing Phase 4 unit/mock cases cover their check logic, but not this extension's real-network CLI boundary. No browser/TLS security effectiveness is established by a loopback HTTP server.
