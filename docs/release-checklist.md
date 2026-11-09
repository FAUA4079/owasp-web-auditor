# Minimal release checklist (research prototype)

## Automated acceptance

```bash
python -m pytest -q
python -m auditor.rules --validate
python -m compileall -q auditor tools
python -m auditor --list-checks
python -m pip install build
python -m build
```

Run these with a clean venv on Kali, and confirm the complete suite passes. Also check the generated wheel in a fresh venv, not only editable mode.

## Explicitly outstanding / non-blocking

- Independent review remains `PENDING` for BenchmarkTest00016 and BenchmarkTest00087. No approval can be inferred from CLI success.
- Remaining 13 selected benchmark cases are `UNEXECUTED`. Precision/recall not established.
- AI explanation is optional, not authoritative. It cannot create detections, source labels, or evidence.
- Human inspection of redacted reports is required before sharing.

## Before publishing on GitHub or distributing

1. Choose a LICENSE **with owner permission**; do not assume copyright/license rights from the project name.
2. Review all source, fixtures, datasets, generated artefacts and logs for credentials, private addresses, and licensing issues.
3. Use GitHub branch protection and run CI against the published commit. Record its SHA-256 archive hash.
4. Verify the pinned official OWASP Benchmark Java commit and CSV digest before making benchmark claims.
5. Document scope, ethical authorization, scanner limitations, false positives and abstentions accurately.

## Local backup

Keep the Kali-verified `owa-phase7-3` source and the separate existing `research/phase7_2/live-01` evidence directory unchanged. Do not put live evidence into distributable ZIPs.
