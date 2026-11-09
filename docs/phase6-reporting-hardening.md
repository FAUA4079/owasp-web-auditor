# Phase 6 — Deterministic reporting and AI hardening

## Scope and trust boundary

Phase 6 operates on the Phase 5 Authenticated RBAC E2E source. CHK01–CHK13 detection functions, role-based access policy requirements, request budgets and deterministic verdicts remain unchanged. AI is still optional explanatory prose and never generates check definitions, test labels, findings, severity or evidence. `results/tests.json`, `results/findings.json`, and `evidence/*.json` are the source of truth, not `results/ai.json` or `results/ai_review.json`.

## Controls implemented

1. **Conservative model-response guardrails.** Existing JSON schema validation, duplicate-key rejection, localized English checks, bounded response size and evidence reference ownership are retained. Additional rules reject obvious prompt-injection phrasing, categorical claims such as "confirmed SQL injection" and recognizable emails, Bearer tokens and secret assignments in generated prose. Rejected responses remain unavailable/partial and preserve deterministic findings. These lexical checks are deliberately conservative and **cannot detect every hallucination or private string**; accepted prose is still unverified.
2. **Evidence-aware AI cache.** AI explanation source fingerprint now includes `evidence/*.json` as well as deterministic scan, test and finding files. Changed evidence hides stale AI prose; the AI evidence review path independently validates hashed evidence and cross-linked test IDs.
3. **Deterministic byte manifest.** `tools/phase6_hardening.py --snapshot` records SHA-256 for `scan.json`, tests, findings, optional coverage/integrity, and every evidence JSON. `--verify` checks exact bytes and the complete file inventory. AI and HTML files are intentionally excluded so provider availability or re-generation does not affect deterministic-source fingerprints. This is an **unsigned** local integrity receipt; an attacker who can edit both source and manifest can replace them. The manifest does not prove evidence authenticity or vulnerability correctness.
4. **Opt-in HTML privacy export.** `--export-private OUTPUT` renders a new HTML file from validated results using best-effort recursive redaction for obvious credentials, auth strings, email addresses, session/cookie fields and query-parameter secrets. The original report and deterministic JSON are not edited. Never treat this best-effort export as a guarantee that arbitrary personal information or arbitrary target strings are absent. Manually inspect before sharing; keep raw scan data private.
5. **Offline provider fallback.** Existing implementation already produces and preserves deterministic JSON/HTML reports when Ollama cannot be reached; status and safe reason are recorded in the AI metadata. Existing connection-failure tests continue to run. AI responses are schema-checked before acceptance; no provider traffic is used by the Phase 6 manifest/export CLI.

## Kali usage

```bash
cd ~/Downloads/owa-phase6
source .venv/bin/activate
python -m pytest -q
python -m auditor.rules --validate

# After any completed scan, use its actual run directory:
RUN="runs/example/scan-actual-id"
python tools/phase6_hardening.py --run "$RUN" --snapshot
python tools/phase6_hardening.py --run "$RUN" --verify
python tools/phase6_hardening.py --run "$RUN" --export-private "$RUN/reports/report-private.html"
```

The following operations occur **locally only**; the manifest command does not call Ollama or targets. Do not use `--snapshot` to hide a failed `--verify`: recapturing after alterations creates a *new* baseline and does not establish that the old baseline was valid.

## Testing and limitations

Phase 6 tests exercise mutation detection, AI-independent hash consistency, symlink rejection, export redaction without source mutations, and adversarial-model-prose rejection. Existing tests cover unreachable Ollama, invalid JSON, source-changed AI cache, HTML escaping, evidence ownership and review store validation. The source manifest is optional; it is not automatically generated for all scans. CHK13 E2E remains a first-party localhost lab, not a third-party vulnerability benchmark. A model can still fabricate a plausible statement that passes schema and lexical guardrails, so human verification remains mandatory.
