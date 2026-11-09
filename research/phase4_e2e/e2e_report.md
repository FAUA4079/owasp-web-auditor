# Phase 4 Extension — Real localhost CLI integration

This is a controlled, **first-party** holdout evaluation. No published independent benchmark was executed.

- Local server scenarios: 5
- Expected-status assertions: 19 passed
- Full subprocess CLI, HTTP/TCP localhost, JSON schema, HTML output and integrity audit: passed
- Evidence tampering detected on copied run files in each case
- AI connection deliberately unavailable; no AI-generated classifications were used

| Scenario | Status checks | Requests | Evidence files |
|---|---:|---:|---:|
| hardened_html | 5 | 1 | 4 |
| missing_headers | 5 | 1 | 4 |
| traceback_disclosure | 4 | 1 | 4 |
| directory_index | 4 | 1 | 4 |
| marker_reflection | 1 | 2 | 1 |

## Limits
- Cases were written for this project, not borrowed from an independently labeled benchmark.
- Exact observed status is tested; **Potential** remains a preliminary indicator, not confirmed exploitation.
- Loopback HTTP does not validate real TLS, browser frame policies or external environment behavior.
- AuditShop authenticated CLI execution and an independent external benchmark remain pending.
- Tests validate known fixture markers; no blanket confidentiality claim for arbitrary data.
- An AI-provider connection was attempted by existing optional reporting, but it was unavailable and no generated advice was used.
