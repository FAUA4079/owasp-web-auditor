# Authenticated assessment — 0.2.0.dev0

This development release implements CHK09–CHK12 for the explicit AuditShop JSON
adapter. It is a tested increment, not completion of the entire original project.
Public CHK01–CHK08 scans remain available as a separate mode. Neither mode claims
all vulnerabilities or complete coverage of any OWASP category.

## Update an existing installation

Finish paused public scans or retain their old source environment first. A source
update changes the resume fingerprint. Completed reports remain readable.

```sh
cd ~/owasp-web-auditor
.venv/bin/python install_authenticated_assessment.py
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/owasp-auditor --version
.venv/bin/owasp-auditor --list-checks
```

The installer creates `.authenticated-backups/`, refuses mismatched source,
validates Python syntax and rolls back on a failed write. It never scans, logs in,
pushes Git commits or resets a lab. It expects the preceding project-session
update. Keep your existing virtual environment and AI environment settings.

For a clean installation from the bundled source directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

Python 3.11+ is required. Release checks were run on Python 3.12, not the user's
Kali Python 3.13 or Windows installation.

## First assessment against fixed AuditShop

Keep the current fixed lab running at `http://127.0.0.1:8088`. The provided config
names two customer identities and declares order 1001 as private to customer A
and order 1002 as private to customer B. This ownership policy is an input to the
test, not inferred by AI.

```sh
.venv/bin/owasp-auditor \
  --project config/auditshop.assessment.json \
  --validate-project

.venv/bin/owasp-auditor \
  --project config/auditshop.assessment.json \
  --assess --prompt-credentials
```

Enter `alice@example.test` and its lab password for `customer_a`, then
`bob@example.test` and its lab password for `customer_b`. Passwords are hidden;
do not paste them into chat. With `--prompt-credentials`, passwords are read in
this process rather than command-line arguments or a credential file.
Without that option, the named credential environment variables are required,
as documented in `project-sessions.md`.

Typical fixed-fixture output before AI processing:

```text
Run: /home/kali/owasp-web-auditor/runs/scan-<generated-id>
Authenticated assessment: no session checkpoint; Ctrl+C saves completed results.
CHK09: No Issue Observed
CHK10: No Issue Observed
CHK09: No Issue Observed
CHK10: No Issue Observed
CHK11: No Issue Observed
CHK12: No Issue Observed
CHK12: No Issue Observed
Integrity audit: PASS
```

With two resources and two accounts, successful complete execution makes 31 target
requests: 6 login/identity requests, 12 ownership/guest controls, 7 catalogue
requests and 6 logout/replay requests. Model API calls are separate and do not
count as target requests. A smaller budget can produce partial results.

## Automatic AI

Normal `--assess` always attempts both English AI explanations and evidence
reviews. The AI receives allowlisted booleans/counts, scanner statuses and evidence
aliases; it does not receive credentials, cookies, CSRF tokens, target URLs, order
IDs, private markers or raw responses. Its prose does not change scanner verdicts.

For your Windows Ollama tunnel, use the port that currently responds from Kali:

```sh
export OWA_AI_PROVIDER=ollama
export OWA_AI_ENDPOINT=http://127.0.0.1:11437
export OWA_AI_MODEL=qwen3:8b
```

11437 is an example from the existing tunnel, not an automatically discovered port.
Check `/api/tags` on your active tunnel first. The Windows SSH tunnel must remain
open. A hosted provider can be selected using the existing flags:

```text
--ai-provider openai-compatible
--ai-endpoint https://YOUR_PROVIDER/v1
--ai-model YOUR_MODEL
--ai-key-env OWA_AI_API_KEY
```

The key belongs in the specified environment variable, never in project JSON.
If AI is unreachable, evidence and HTML remain available with an explicit AI
unavailable/partial status. To retry AI without new target requests:

```sh
.venv/bin/owasp-auditor-report --run runs/scan-YOUR_RUN
```

## New checks and evidence

| Check | Test | Positive conclusion | Limits |
| --- | --- | --- | --- |
| CHK09 | Owner, unrelated customer, owner repeat | Confirmed when private order ID, owner and marker match stable owner controls | Only configured resources and declared ownership policy |
| CHK10 | Owner, isolated anonymous request, owner repeat | Confirmed when the same private order is disclosed without a session | No broad authentication-bypass coverage |
| CHK11 | Catalogue baseline, random negative control, two boolean probe pairs, baseline repeat | Potential for a repeatable true/false differential | No database dump, writes, time delays or independent SQL execution proof |
| CHK12 | Verified `/api/me`, logout, old-cookie replay | Confirmed when the old cookie still returns the same user and role | Immediate replay only; no multi-node or long-term invalidation assessment |

401/403/404 denial on the ownership checks is `No Issue Observed` only for that
resource/actor. HTTP 200 alone never confirms access disclosure. Missing valid
controls, redirects, unstable observations and operational limits are inconclusive.

Files are stored in `runs/scan-.../`:

- `scan.json`: scope, mode, completion and total request count.
- `request_ledger.json`: attempts, status, byte count and outcome, without payloads.
- `results/tests.json`: each check, status, reason and redacted observations.
- `results/findings.json`: positive results and linked tests/evidence.
- `results/accounts.json`: aliases, verification and cleanup summaries only.
- `results/coverage.json`: all ten categories, with partial/not-tested labels.
- `evidence/*.json`: minimized observations with SHA-256 integrity hashes.
- `results/ai*.json`: English explanations, minimized context, reviews and status.
- `reports/report.html`: human-readable report with separate AI commentary.

```sh
.venv/bin/owasp-auditor-validate --run runs/scan-YOUR_RUN
.venv/bin/owasp-auditor-integrity --run runs/scan-YOUR_RUN
xdg-open runs/scan-YOUR_RUN/reports/report.html
```

## Isolated vulnerable/fixed comparison

Do not overwrite or reset the user's working lab database just to run a benchmark.
The supplied benchmark creates fresh temporary databases and binds temporary
loopback ports for each of `fixed`, `SHOP-01`, `SHOP-03`, `SHOP-04`, `SHOP-14`.
It uses ephemeral test credentials, cleans up its servers and checks report
validation, integrity and omission of fixture secrets. AI network calls are
intentionally excluded from this offline benchmark; AI schemas and mocked provider
responses are covered by unit tests.

The optional benchmark requires Flask in the auditor virtual environment:

```sh
.venv/bin/python -m pip install 'Flask==3.1.3'
.venv/bin/python tools/benchmark_auditshop.py \
  --shop-source ~/auditshop-full-v1/auditshop-lab
```

| Fixture | CHK09 | CHK10 | CHK11 | CHK12 |
| --- | --- | --- | --- | --- |
| fixed | No Issue Observed | No Issue Observed | No Issue Observed | No Issue Observed |
| SHOP-01 | Confirmed | No Issue Observed | No Issue Observed | No Issue Observed |
| SHOP-03 | No Issue Observed | Confirmed | No Issue Observed | No Issue Observed |
| SHOP-04 | No Issue Observed | No Issue Observed | Potential | No Issue Observed |
| SHOP-14 | No Issue Observed | No Issue Observed | No Issue Observed | Confirmed |

## Lifecycle and remaining work

Authenticated assessments persist completed results and the ledger when Ctrl+C
is pressed once, but do **not** save credential/session checkpoints or resume
unfinished authenticated tests. Use a new run to repeat them. Existing public
scan resume is unchanged. AI can be retried independently from saved evidence.
A broken logout implementation can leave server-side sessions valid until expiry
or a deliberate lab reset. Do not treat logout acknowledgement as revocation.

The following are still unimplemented, not silently covered by AI:

1. General website login adapters, MFA/OAuth and per-role authenticated crawling.
2. Admin role/action authorization checks and browser-confirmed reflected/stored XSS.
3. Browser CSRF verification and controlled business mutations with reset/rollback.
4. Price/coupon business-rule verification and other integrity workflows.
5. SBOM/dependency analysis and backend log/alert correlation.
6. Authenticated resume with reauthentication, preserved budgets and credential-free checkpoints.
7. A unified public/authenticated report workflow and broader real-world false-positive evaluation.
8. Final Kali/Python 3.13 verification, GitHub packaging and user-approved publication.

No Git operations or deployment are part of this release. GitHub can store source;
the intentionally vulnerable dynamic backend remains a local test lab.
