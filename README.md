# OWASP Web Auditor

**Research-oriented, bounded web security auditing CLI — v0.2.0rc1 (research prototype)**

> **Not an official OWASP project or OWASP-certified scanner.** It is an independent educational/research implementation. It is **not** a production-ready DAST replacement and cannot certify that any website is secure. Run it **only against systems you own or have explicit authorization to test**.

OWASP Web Auditor combines **13 deterministic security checks (CHK01–CHK13)**, bounded crawling/HTTP requests, opt-in authenticated AuditShop checks, JSON/HTML evidence and integrity verification, and optional **Ollama** AI explanations. AI is **never used to define detection rules, assign vulnerability verdicts, invent evidence or create benchmark ground-truth labels**.

## Features at a glance

| Area | Capability |
| --- | --- |
| Public HTTP checks | CHK01–CHK08: selected HTTPS/header, cookie, error disclosure, directory listing, reflection and exceptional-input checks |
| Authenticated lab checks | CHK09–CHK13: opt-in AuditShop-specific authorization/session checks, including CHK13 human-approved RBAC policy |
| Scanning boundaries | Limited requests/time/crawl depth/response sizes; same-origin scope; standard TLS verification enabled |
| Evidence/reporting | JSON evidence, request ledger, HTML report, resumable runs and optional SHA-256 source manifest |
| AI reporting | Local Ollama or OpenAI-compatible provider, optional explanatory text and review; deterministic findings remain authoritative |
| Research | Traceability to rule metadata, reproducible first-party E2E tests, external benchmark provenance and review-gated scoring |
| Test/release | Python `pytest` suite, GitHub Actions CI, Python wheel and sdist builds |

## Project status and scientific limitations

- **Last independently supplied Kali RC1 verification:** Python 3.14, **232 tests and 41 subtests passed**; **13 metadata records schema-valid**; CLI version `0.2.0rc1`; wheel and source distribution built successfully. Your own GitHub Actions runs must be checked after publishing.
- A subset of **OWASP Benchmark Java 1.2** was evaluated using the existing CHK04 detector: `BenchmarkTest00016` was `No Issue Observed`, and `BenchmarkTest00087` was `Potential`. **Human review is still pending**; do not advertise these as final TP/TN counts. Other selected external benchmark cases are unexecuted.
- A `Potential` finding is **not** a proven vulnerability. Passing unit/E2E tests does **not** establish real-world sensitivity, precision or recall.
- CHK09–CHK13 have an **AuditShop-specific authenticated adapter**; they do not automatically test arbitrary websites.
- This repository does **not** include sensitive scan runs, stored credentials, VM artifacts or live benchmark captures.

## Requirements

- Linux/Kali recommended (Python **3.11+**; tested on Kali Python 3.14)
- `python3`, `python3-venv`, `git`, a terminal, and internet access **only to download Python dependencies**
- Optional: Windows Ollama `qwen3:8b` through SSH reverse port forwarding to a Kali VM
- Optional: Docker for self-owned local benchmark/lab applications

Do not use system-wide `sudo pip install`; use a project virtual environment.

## 1. Clone from GitHub and install (fresh Kali)

When this repository has been published, replace `YOUR_REPOSITORY_NAME` with its actual name:

```bash
git clone https://github.com/FAUA4079/YOUR_REPOSITORY_NAME.git
cd YOUR_REPOSITORY_NAME
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e . pytest build
python -m auditor --version
python -m auditor --list-checks
python -m auditor.rules --validate
python -m pytest -q
python -m build
```

You should see `auditor 0.2.0rc1`; the test count may change if the repository is updated. `python -m build` creates `dist/*.whl` and `dist/*.tar.gz` for this Python package.

**No AI server is required for deterministic scanning, testing or building the package.**

### Install only the wheel (alternative)

```bash
python3 -m venv ~/owa-wheel-env
source ~/owa-wheel-env/bin/activate
python -m pip install ./dist/owasp_web_auditor-0.2.0rc1-py3-none-any.whl
owasp-auditor --version
```

## 2. First scan: your own localhost demonstration

**Kali terminal A** (keep this running):

```bash
mkdir -p /tmp/owa-demo
printf '<html><body><h1>Local OWA Demo</h1></body></html>\n' > /tmp/owa-demo/index.html
python3 -m http.server 8765 --bind 127.0.0.1 --directory /tmp/owa-demo
```

**Kali terminal B** (from the repository virtual environment):

```bash
cd YOUR_REPOSITORY_NAME
source .venv/bin/activate
python -m auditor \
  --url http://127.0.0.1:8765/ \
  --no-crawl \
  --output runs/local-demo
```

The command prints a generated directory like `runs/local-demo/scan-<id>` containing `reports/report.html`, `scan.json`, `results/` and `evidence/`. Find/open the report with:

```bash
find runs/local-demo -path '*/reports/report.html' -type f -print
# Replace with the path printed by the scan:
xdg-open runs/local-demo/scan-ACTUAL_ID/reports/report.html
```

The minimal Python server may produce `Potential` observations because it does not configure production security headers. This is a **local demonstration**, not an external security assessment.

## 3. Optional AI setup — Windows Ollama to Kali VM

The supported example below uses **Windows host Ollama** and **Kali Linux as a VirtualBox guest**. Ollama runs on Windows at `127.0.0.1:11434`; a **reverse SSH tunnel** exposes it *only inside Kali* at `127.0.0.1:11437`. This avoids exposing the model API to the LAN or internet.

### A. Windows PowerShell — start/check Ollama

Install [Ollama](https://ollama.com/download) on Windows, then:

```powershell
ollama --version
ollama pull qwen3:8b
ollama list
Invoke-RestMethod http://127.0.0.1:11434/api/tags
```

Ollama may already run as a Windows app/service. If `ollama serve` reports `address already in use`, that often means the API is **already running**; do not start a second copy. `qwen2.5-coder:7b` is an optional model alternative but is not required.

### B. Kali — verify SSH server

```bash
sudo systemctl enable --now ssh
sudo systemctl status ssh --no-pager
sudo ss -lntp | grep ':22'
```

If `openssh-server` is absent, install it using Kali's package manager **after resolving any existing dpkg errors**.

### C. Windows — confirm host-to-guest SSH access

If you already have VirtualBox NAT port forwarding mapping Windows loopback `2222` to Kali port `22`, test:

```powershell
ssh -p 2222 kali@127.0.0.1
```

After login, type `exit`. **Do not duplicate an existing port-forwarding rule.** If SSH access is unavailable, use VirtualBox's **Network > Adapter > Advanced > Port Forwarding** to create a rule: TCP, host IP `127.0.0.1`, host port `2222`, guest port `22`; configure guest IP to your actual Kali NAT address if required. This is specific to your VirtualBox network setup. Refer to [VirtualBox documentation](https://www.virtualbox.org/manual/ch06.html).

### D. Windows — open a persistent reverse SSH tunnel

In **a separate Windows PowerShell window**:

```powershell
ssh -NT `
  -o ExitOnForwardFailure=yes `
  -o ServerAliveInterval=30 `
  -p 2222 `
  -R 127.0.0.1:11437:127.0.0.1:11434 `
  kali@127.0.0.1
```

Enter the Kali account password. **No output is normal. Leave this terminal open** during AI scans. The tunnel is broken when this SSH process exits.

### E. Kali — prove real model inference works

```bash
curl -fsS http://127.0.0.1:11437/api/tags | python3 -m json.tool
curl --connect-timeout 10 --max-time 180 -fsS \
  http://127.0.0.1:11437/api/generate \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen3:8b","prompt":"Reply with exactly: OWA CONNECTION OK","stream":false,"think":false,"options":{"num_predict":32}}' \
  | python3 -m json.tool
```

Expect a JSON response with `"done": true` and `"response": "OWA CONNECTION OK"` (or equivalent). The initial inference may need time to load the model.

### F. Kali — run the auditor with optional AI explanations

From the cloned repository virtual environment, with your localhost demo server still running:

```bash
export OWA_AI_PROVIDER=ollama
export OWA_AI_ENDPOINT=http://127.0.0.1:11437
export OWA_AI_MODEL=qwen3:8b

python -m auditor \
  --url http://127.0.0.1:8765 \
  --no-crawl \
  --output runs/ollama-demo \
  --ai-provider ollama \
  --ai-endpoint http://127.0.0.1:11437 \
  --ai-model qwen3:8b
```

The CLI may print `AI explanation ...` and `AI report: complete`; `results/ai.json` records model/provider status. **AI failure does not change deterministic CHK findings.** Never use AI output as evidence or a final security verdict.

**Alternative: Ollama running on Kali** (no tunnel): use `http://127.0.0.1:11434` instead. More provider details: [`docs/automatic-ai.md`](docs/automatic-ai.md).

### Windows–Kali AI troubleshooting

| Problem | What to check |
| --- | --- |
| Windows Ollama port already bound | `Invoke-RestMethod http://127.0.0.1:11434/api/tags`; do not start another `ollama serve` |
| `ssh -p 2222` fails | Kali SSH service and VirtualBox NAT port forwarding, account name and port |
| Kali `11437` connection refused | Keep `ssh -NT -R ...` open; check `curl /api/tags` first |
| `/api/tags` works, AI response is slow | Initial model loading; `ollama ps` on Windows; allow time for first inference |
| Scanner reports AI unavailable | Verify environment variables, model name, endpoint and tunnel; deterministic report remains usable |
| Security report flagged issues on localhost | A demo Python HTTP server lacks some expected policies; `Potential` is not confirmed exploitation |

## 4. Authenticated AuditShop lab (optional, advanced)

CHK09–CHK13 are for an **explicitly approved AuditShop-compatible local environment**, not arbitrary websites. The example JSON files refer to `http://127.0.0.1:8088`. They do **not** start the application for you. Use only your own isolated lab, preferably a disposable dataset.

Start with offline validation:

```bash
python -m auditor \
  --project config/auditshop.rbac.project.example.json \
  --validate-project
```

For live preflight, define account email/password variables **only in your local shell, never in Git**:

```bash
export AUDITSHOP_A_EMAIL='YOUR_LAB_CUSTOMER_A_EMAIL'
export AUDITSHOP_A_PASSWORD='YOUR_LAB_CUSTOMER_A_PASSWORD'
export AUDITSHOP_B_EMAIL='YOUR_LAB_CUSTOMER_B_EMAIL'
export AUDITSHOP_B_PASSWORD='YOUR_LAB_CUSTOMER_B_PASSWORD'
export AUDITSHOP_ADMIN_EMAIL='YOUR_LAB_ADMIN_EMAIL'
export AUDITSHOP_ADMIN_PASSWORD='YOUR_LAB_ADMIN_PASSWORD'

python -m auditor \
  --project config/auditshop.rbac.project.example.json \
  --check-accounts
```

To enable CHK13, **create a local, human-approved copy** of `config/rbac.policy.example.json` with your actual reviewer, approval reference, authorized test scope and `authorized_for_testing=true`. Do not commit that approved local policy or credentials. Run the authenticated assessment only after preflight succeeds:

```bash
python -m auditor \
  --project config/auditshop.rbac.project.example.json \
  --rbac-policy /path/to/your-approved-local-policy.json \
  --assess \
  --output runs/authorized-lab
```

Read [`docs/authenticated-assessment.md`](docs/authenticated-assessment.md), [`docs/phase5-rbac.md`](docs/phase5-rbac.md) and [`docs/phase5-authenticated-e2e.md`](docs/phase5-authenticated-e2e.md) first. These checks can exercise authentication and data-access paths; only run them under written authorization.

## 5. Offline evidence integrity and privacy export

For a completed run, use its **actual** printed directory:

```bash
RUN='runs/ollama-demo/scan-ACTUAL_ID'
python tools/phase6_hardening.py --run "$RUN" --snapshot
python tools/phase6_hardening.py --run "$RUN" --verify
python tools/phase6_hardening.py --run "$RUN" \
  --export-private "$RUN/reports/report-private.html"
```

SHA-256 manifests establish that files are unchanged **relative to your own snapshot**; they are not cryptographic proof that the original scan was genuine. Privacy redaction is **best-effort**; manually inspect any report before sharing. Raw evidence and run directories must remain private.

## 6. Benchmark evaluation and reproducibility

The repository contains source provenance, human-review gates, and CHK04 adapter tooling. The external OWASP Benchmark Java fixture is **not executed during normal scanning**. Do not claim benchmark accuracy unless labels, endpoint compatibility, raw evidence, detector replay, and human attestations have all been verified. The 15-case subset has 13 unexecuted cases; two CHK04 observations were pending human review at RC1.

- [`docs/phase7-independent-evaluation.md`](docs/phase7-independent-evaluation.md)
- [`docs/phase7-2-benchmark-chk04.md`](docs/phase7-2-benchmark-chk04.md)
- [`docs/phase7-3-review.md`](docs/phase7-3-review.md)

## 7. Run tests, build a release and verify a clean clone

```bash
python -m pytest -q
python -m auditor.rules --validate
python -m auditor --version
python -m pip install build
python -m build
ls -lh dist/
```

For a clean install check, clone into a **new** directory and follow section 1. Before deleting any local files, confirm that the public repository includes `auditor/`, `config/`, `docs/`, `lab/`, `research/`, `tests/`, `tools/`, `pyproject.toml`, `README.md`, and `.github/workflows/ci.yml`; that `pytest` passes; and that a local demo scan succeeds. **Back up private lab data, credentials, uncommitted changes and scan evidence separately**: these are deliberately not in Git.

## Repository layout

```text
auditor/       CLI entrypoints, deterministic checks, authenticated adapter,
               HTTP transport, crawler, AI integration, reporting, rules, integrity
config/        Example public profile and AuditShop lab configs
lab/           First-party localhost fixture servers
research/      Research traceability, benchmark metadata and score baselines
tests/         Automated checks, regression, adversarial and E2E tests
tools/         Evidence integrity, research mapping and evaluation CLIs
docs/          Technical guides for every research/prototype milestone
.github/       GitHub Actions CI configuration
pyproject.toml Python package metadata, dependencies and entry points
```

## Attribution, privacy, license and contact

- This is an **independent** research prototype and is not affiliated with or endorsed by the OWASP Foundation.
- Original external benchmark sources and other datasets retain their own terms. Review [`research/`](research/) and citations before redistribution.
- **License decision pending:** No open-source license has been selected in this source archive. Public GitHub visibility **does not automatically grant permission to reuse or redistribute this code**. The repository owner should explicitly select a license after reviewing ownership and third-party material.
- Never commit `.env`, passwords, API keys, raw scan evidence, approved private RBAC policies or personal datasets. The `.gitignore` helps but is not a security substitute for reviewing every commit.
