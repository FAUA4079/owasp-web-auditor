# Check selection and crawl policy

List implemented checks without a target, scan directory, AI call or network request:

```bash
.venv/bin/owasp-auditor --list-checks
```

Select a comma-separated set of rule IDs:

```bash
.venv/bin/owasp-auditor --url http://127.0.0.1:8001/discovery.html \
  --checks CHK02,CHK03 --no-crawl
```

`--checks` accepts CHK01 through CHK08 (case-insensitive); duplicates are removed.
Omitting it, or using `--checks all`, preserves the existing behavior: all eight
rules are considered, but prerequisites still determine what can be executed.
An explicit list containing CHK07 requires `--reflection-param`; CHK08 requires
`--exception-param`. A parameter for a rule excluded from the list is rejected
before target requests or run creation. Empty/unknown rule IDs are rejected.

## Rule modes

| Rule | Purpose | Request behavior |
| --- | --- | --- |
| CHK01 | HTTP root HTTPS redirect handling | Bounded HTTP root and redirect checks |
| CHK02 | Framing policy | Inspects fetched response headers |
| CHK03 | Content-Type and nosniff | Inspects fetched response headers |
| CHK04 | Cookie attributes | Inspects fetched response headers |
| CHK05 | Error disclosure indicators | Inspects bounded fetched text |
| CHK06 | Directory listing indicators | Inspects eligible fetched HTML |
| CHK07 | Harmless marker reflection | Explicit baseline and marker requests |
| CHK08 | Exceptional numeric input | Explicit baseline and malformed input requests |

Response inspection is not a traffic-free mode: the target must be fetched.
CHK02 and CHK03 share header parsing/evidence, but only selected rule outcomes
and findings are retained. Discovery still uses directory-listing recognition
to avoid expanding listed files, even when CHK06 is excluded from reporting.

When selecting only CHK01 or query probes, no separate page-discovery task is
scheduled. Probe-only CHK07 normally uses two requests, not three, because the
unneeded initial page fetch is omitted. Existing redirects, failures and budgets
can affect totals. Reflection does not confirm XSS; CHK08 does not confirm SQLi.

## Single-page mode

`--no-crawl` prevents following discovered links. The supplied page can still
produce an inventory; eligible links are marked `crawling_disabled`. This is an
intentional policy, not a depth-limit failure. Permitted redirect chains and
explicit CHK01/CHK07/CHK08 requests are not disabled by this flag. It does not
mean exactly one request. Forms remain inventory-only and are never submitted.

Without `--no-crawl`, existing profile depth and static-HTML restrictions apply.
This release does not expand scope: existing origin checks, redirect restrictions,
TLS verification and shared request/time budgets remain in force.

## Reports and resume

Excluded rules get one `Not Tested` record per run with the reason
`Disabled by operator check selection.` These are not executed tests and do not
count as assessed coverage. Selected response rules can have multiple records
when multiple pages are inspected. The HTML summary displays selected IDs and
whether discovered links can be followed. `scan.json`, `checkpoint.json` and
`results/plan.json` preserve the policy and selection reasons.

Resume preserves the original selection and crawl policy:

```bash
.venv/bin/owasp-auditor --resume runs/scan-YOUR_RUN_ID
```

Do not pass `--checks` or `--no-crawl` on resume. Start a new scan to change them.
AI provider arguments remain available on resume and are independent of checks.
Finish paused scans before installing this update: code fingerprints change.
Historical saved results can still be used by the report regeneration command.

## Automatic English AI

AI remains automatic and supports the provider configuration from
`docs/automatic-ai.md`. For the Windows-to-Kali tunnel setup:

```bash
export OWA_AI_PROVIDER=ollama
export OWA_AI_ENDPOINT=http://127.0.0.1:11436
export OWA_AI_MODEL=qwen3:8b
```

The target server, Windows Ollama and SSH tunnel must be started separately.
AI failure preserves scanner output and is shown separately in the report.

## Installation

Install the preceding English AI provider update (`install_ai_providers.py`)
first. Then run `install_check_selection.py` from the project directory.
The installer checks the expected source, backs up modified files under
`.selection-backups`, and performs no scans or Git operations. If it detects a
source mismatch, it stops without overwriting the differing files.

Run the suite:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Tests cover selection validation, evidence references, coverage, no-crawl,
crawled-page filtering, probe-only requests, cancellation/resume, network failure,
and offline check listing. Provider and target responses in automated tests
are simulated; verify your actual environment with an authorized local target.
