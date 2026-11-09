# OWASP Web Auditor 0.1.0

A development CLI for bounded web configuration observations, selected input
checks, evidence records and self-contained HTML reports. It is not an exhaustive
OWASP Top 10 assessment or an exploitation framework. Potential findings need
contextual confirmation. Zero findings does not establish that a target is secure.

## Install on Kali/Linux

Python 3.11 or newer is required. Development tests have run on Python 3.12;
user-side tests have run on Kali Python 3.13. Resume uses POSIX file locking;
native Windows is not supported. Run the tool inside Kali or another Linux environment.

From the project directory:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/owasp-auditor --version
.venv/bin/owasp-auditor --help
.venv/bin/python -m unittest discover -s tests -v
```

For an existing virtual environment, reuse it and run only the install command.
`pip install -r requirements.txt` is an alternative to `pip install -e .`.
No `sudo pip` is needed. Installation needs access to the Python package index.
The supported console commands and `python -m auditor` use the same dispatcher.
Activate the virtual environment (`source .venv/bin/activate`) to use command
names without their `.venv/bin/` prefix.

## Basic scan

Use a target you own or are authorized to assess. Start your local demo server
separately; the auditor does not start target applications.

```bash
.venv/bin/owasp-auditor --url http://127.0.0.1:8001/discovery.html
# Equivalent:
.venv/bin/python -m auditor --url http://127.0.0.1:8001/discovery.html
```

Choose a configuration/output directory explicitly when needed:

```bash
.venv/bin/owasp-auditor --url http://127.0.0.1:8001/ \
  --profile config/public.json --output runs
```

If `--profile` is omitted, an existing `config/public.json` in the current
working directory takes precedence; otherwise the installed public profile is
used. An invalid local/explicit profile fails rather than silently falling back.
The bundled profile allows 50 attempted requests, 10 seconds per request,
120 seconds active scan time, 1 MiB per response, depth 2 and 5 redirects.
TLS verification is required. All requests share the budget.
Outputs default to `runs/` relative to the current working directory.

The top-level target must not contain credentials or query parameters. Explicit
parameter probes generate their own values. Fragments are discarded.

## Explicit parameter checks

Select only read-only inputs appropriate for the stated test:

```bash
.venv/bin/owasp-auditor --url http://127.0.0.1:8002/search --reflection-param q
.venv/bin/owasp-auditor --url http://127.0.0.1:8003/item --exception-param id
```

Reflection checks use a harmless marker and do not demonstrate XSS. Exceptional
input checks compare numeric baseline `1` to one malformed value; they do not
establish SQL injection. Probe redirects are not followed. Forms are never submitted.

## Pause and resume

Press Ctrl+C once and wait for graceful checkpoint/output saving. Resume using
the actual run directory printed by the tool:

```bash
.venv/bin/owasp-auditor --resume runs/scan-YOUR_RUN_ID
# Equivalent:
.venv/bin/python -m auditor --resume runs/scan-YOUR_RUN_ID
```

Use `--resume` without a new target, profile, output or probe option.
AI provider options may be supplied for the report stage.
The original settings and request/active-time budgets are preserved. Paused
wall-clock time is excluded. Completed tasks are kept; an interrupted task or
baseline/probe pair may repeat and consumes the remaining request budget.
Results can span sessions and target content can change between them.
Completed runs do not send requests again. Exhausted budgets are not reset.
Runs created before checkpoint support cannot be resumed. Force-kill, power
loss and repeated Ctrl+C are not equivalent to graceful cancellation.
Finish pending scans before code or environment upgrades; changed fingerprints
are rejected. Never run two processes against the same run directory.

## Reports and validation (no target requests)

Reports include automatic English AI explanations using local Ollama or an
HTTPS Chat Completions-compatible API. See `docs/automatic-ai.md` for command
options, API-key setup, retries and data handling. The report command contacts
the configured AI provider when needed; it does not contact the target.

Replace `scan-YOUR_RUN_ID` with the actual run name:

```bash
.venv/bin/owasp-auditor-validate --run runs/scan-YOUR_RUN_ID
.venv/bin/owasp-auditor-integrity --run runs/scan-YOUR_RUN_ID
.venv/bin/owasp-auditor-report --run runs/scan-YOUR_RUN_ID
firefox runs/scan-YOUR_RUN_ID/reports/report.html
```

Module equivalents:

```bash
.venv/bin/python -m auditor.reporting.validation --run runs/scan-YOUR_RUN_ID
.venv/bin/python -m auditor.verification.integrity --run runs/scan-YOUR_RUN_ID
.venv/bin/python -m auditor.reporting.html_report --run runs/scan-YOUR_RUN_ID
```

Schema validation covers report input structure/types, not every output file.
The integrity audit checks saved references, hashes, request accounting and
known fixture markers; it is not authentication or a full secret scan.
See `docs/reporting.md` for details. The HTML report loads no external assets.
Missing session history in pre-resume runs is expected.

## Implemented checks

| Rule | Observation | Main limitation |
| --- | --- | --- |
| CHK01 | HTTP root HTTPS redirect handling | Root URL only; no complete TLS review |
| CHK02 | Framing policy indicators | Policy presence does not establish effectiveness |
| CHK03 | Content-Type and nosniff | MIME/browser behavior not verified |
| CHK04 | Selected cookie attributes | Cookie purpose and authentication impact unknown |
| CHK05 | Python/PHP error structures | Documentation may match; other formats untested |
| CHK06 | Common English directory listings | No file contents requested or intent assessed |
| CHK07 | Harmless query reflection | Reflection is not XSS |
| CHK08 | Numeric input error handling | One baseline/value; not injection confirmation |

The bounded crawler follows eligible query-free .html/.htm links, honors scope
and depth, skips duplicates, inventories forms without submitting them and does
not execute JavaScript. Recognized directory entries are not expanded.
Coverage lists ten OWASP categories, but only selected aspects of A02/A04/A05/A10
have implemented checks. Other categories require additional testing/evidence.

## Result interpretation and retention

- `Confirmed`: a supported check established its stated condition; no general security guarantee.
- `Potential`: an observation requires contextual confirmation.
- `Inconclusive`: the check cannot support a reliable conclusion.
- `No Issue Observed`: no issue observed only for this particular executed check.
- `Not Tested`: prerequisites were unmet or the check was not selected.

`finished` describes run processing, not full category coverage. Review skipped
checks, limitations, stop reasons and missing results before interpreting counts.
Query/form values and raw cookie values are omitted by the implemented paths.
URL paths and input names are retained. Do not assume every possible secret is
redacted. Keep real scan results and checkpoints out of public repositories.

Each run can contain scan.json, checkpoint.json, request_ledger.json,
results/{tests,findings,findings_raw,plan,coverage,integrity}.json,
discovery/endpoints.json, evidence/*.json and reports/report.html.

## Troubleshooting

- `Address already in use`: the demo port is occupied. Use the existing intended server or select another port and update the target URL.
- `network_error`: verify the server is still running and the URL/port is correct.
- `response_not_declared_html`: discovery intentionally skipped non-HTML content.
- `Not Tested`: read the rule's reason; it is not automatically a tool error.
- `ModuleNotFoundError`: use the project's venv and rerun `pip install -e .`.
- Schema failure: inspect the identified file/field. Do not edit a result just to force PASS.
- Changed checkpoint fingerprint: restore the original code/environment or start a new run.
- `Executing <Task ...> took ...`: unittest asyncio timing diagnostics can appear even when all tests pass.

The legacy `auditor.probe` and `auditor.run_check` development modules are not
the supported scan entry point. Prefer `owasp-auditor` / `python -m auditor`.

## Build a wheel

```bash
.venv/bin/python -m pip wheel --no-deps . --wheel-dir dist
```

The wheel includes the default profile, report template and JSON schemas.
Dependencies still need to be installed by pip when installing the wheel.
No repository URL or license grant is invented by this package. Publication,
license selection and the final GitHub push remain separate release work.

## Select checks and control discovery

Use `--list-checks` without a URL to list supported rules. Use
`--checks CHK02,CHK03 --no-crawl` to inspect only the supplied page for those
checks. AI remains automatic. See `docs/check-selection.md` for prerequisites,
request behavior and resume rules.

## AI review foundation

Independent review storage and evidence validation are available via
`python -m auditor.review.store --run runs/scan-YOUR_RUN_ID --init` and
`--validate`. This foundation performs no AI generation or target requests and
does not change scanner verdicts. See `docs/ai-review-foundation.md`.

## Structured AI review context

Use `python -m auditor.review.context --run runs/scan-YOUR_RUN_ID --build`
and `--validate` to prepare/verify minimized context for CHK05/07/08. New CHK07
scans retain bounded context labels, while old runs report context unavailable.
No model calls are made by these commands. See `docs/ai-review-context.md`.

## Automatic AI evidence reviews

Scans and report regeneration now also build context and generate validated
English CHK05/07/08 reviews. They appear in a separate HTML section. To retry only
this stage, use `python -m auditor.review.generate --run runs/scan-YOUR_RUN_ID`
with the existing AI provider settings. See `docs/ai-review-generation.md`.
