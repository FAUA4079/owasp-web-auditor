# OWASP Web Auditor

**Version:** `0.2.0rc1` — independently developed, research-oriented Python web-security auditing CLI.

> **Not an official OWASP product or certified scanner.** Only scan systems you own or are explicitly authorized to test. This is an educational/research prototype, not a replacement for production DAST or a guarantee of security.

## Features

- 13 deterministic, research-mapped checks (`CHK01–CHK13`), with OWASP ASVS / CWE traceability.
- Passive and bounded active web observations, optional page discovery, and controlled scope.
- Opt-in authenticated assessment and policy-approved RBAC checks for the supported AuditShop-style adapter.
- Structured JSON evidence, request ledger, integrity auditing, and generated HTML reports.
- Optional local Ollama AI explanations and review assistance. AI **does not** generate security rules, labels, evidence or vulnerability verdicts.
- Checkpoint/resume support and privacy-redacted HTML export.
- Reproducible first-party lab tests and a limited external OWASP Benchmark Java evaluation framework.
- GitHub Actions test workflow.

## Requirements

- Linux, including Kali, with Python 3.11+ (the release candidate was verified under Kali Python 3.14).
- Internet connectivity for Python package installation.
- Optional Windows host running Ollama (tested with `qwen3:8b`).
- SSH connectivity from Windows to Kali for the optional AI tunnel.

## Install from a fresh GitHub clone

```bash
git clone https://github.com/FAUA4079/owasp-web-auditor-research.git
cd owasp-web-auditor-research

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e . pytest build

python -m auditor --version
python -m auditor.rules --validate
python -m pytest -q
python -m build
```

Expected CLI version: `auditor 0.2.0rc1`. In the release-candidate Kali verification, **232 tests and 41 subtests passed**. These reflect unit/integration checks, **not** proven vulnerability detection accuracy.

### Basic authorized localhost scan

Terminal 1:

```bash
mkdir -p /tmp/owa-demo
printf '<html><body><h1>Authorized local demo</h1></body></html>\n' > /tmp/owa-demo/index.html
python3 -m http.server 8765 --bind 127.0.0.1 --directory /tmp/owa-demo
```

Terminal 2 (inside the project venv):

```bash
python -m auditor \
  --url http://127.0.0.1:8765 \
  --no-crawl \
  --output runs/local-demo
```

Open the report path printed by the CLI. A basic Python server often lacks security headers; scanner statuses may indicate `Potential` rather than confirmed vulnerabilities.

## Optional AI: Windows Ollama → Kali over an SSH reverse tunnel

This uses **Windows to run the model** and **Kali to run the scanner**. Ollama stays bound to Windows loopback, and the tunnel binds only to Kali loopback.

### 1. Windows: install Ollama and obtain the model

In Windows PowerShell:

```powershell
ollama --version
ollama list
ollama pull qwen3:8b
Invoke-RestMethod http://127.0.0.1:11434/api/tags
```

If the Ollama app/service is already running, do **not** execute a second `ollama serve`: a port-11434 "address already in use" error simply means the listener is occupied.

### 2. Kali: start the SSH server

```bash
sudo systemctl enable --now ssh
sudo systemctl status ssh --no-pager
sudo ss -lntp | grep ':22'
```

If Kali runs in VirtualBox NAT mode, make sure a NAT port-forward exists from Windows `127.0.0.1:2222` to Kali SSH port 22. The VM's precise adapter and guest IP may differ. **Don't add a duplicate NAT forwarding rule.**

Test from Windows PowerShell:

```powershell
ssh -p 2222 kali@127.0.0.1
```

If successful, run `exit` to return to Windows. `kali` is the example username; replace if different.

### 3. Windows: leave the reverse tunnel open

Open a separate Windows PowerShell window:

```powershell
ssh -NT `
  -o ExitOnForwardFailure=yes `
  -o ServerAliveInterval=30 `
  -p 2222 `
  -R 127.0.0.1:11437:127.0.0.1:11434 `
  kali@127.0.0.1
```

After entering the Kali password, a silent SSH window is normal. Keep it open for the scanner session.

### 4. Kali: verify the AI endpoint

```bash
curl -fsS http://127.0.0.1:11437/api/tags | python3 -m json.tool

curl --connect-timeout 10 --max-time 180 -sS \
  http://127.0.0.1:11437/api/generate \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen3:8b","prompt":"Reply exactly: OWA CONNECTION OK","stream":false,"think":false,"options":{"num_predict":32}}'
```

Ensure the response has `"done":true` and contains `OWA CONNECTION OK`. Initial model loading may take extra time.

### 5. Kali: enable optional AI explanations in the scanner

```bash
source .venv/bin/activate

export OWA_AI_PROVIDER=ollama
export OWA_AI_ENDPOINT=http://127.0.0.1:11437
export OWA_AI_MODEL=qwen3:8b

python -m auditor \
  --url http://127.0.0.1:8765 \
  --no-crawl \
  --output runs/windows-ollama-demo \
  --ai-provider ollama \
  --ai-endpoint http://127.0.0.1:11437 \
  --ai-model qwen3:8b
```

Look for `AI report: complete` in the CLI output. AI service unavailability must never be interpreted as a changed deterministic verdict.

### Common AI troubleshooting

| Symptom | Check |
|---|---|
| Windows `ollama serve` says port in use | Ollama likely already running; check `/api/tags`. |
| Kali `/api/tags` connection refused | SSH reverse tunnel has stopped or port is wrong. |
| SSH `-p 2222` refused | VirtualBox NAT forward, Kali `sshd`, and username. |
| Model request slow | Windows `ollama ps`, available RAM, and first model load. |
| Scan succeeds but AI unavailable | Keep deterministic report; check model name, port and tunnel. |

**Privacy:** Only send authorized test material to local Ollama. Avoid feeding real credentials, tokens or private user data into prompts or publishing raw reports.

## Authenticated RBAC assessment

Authenticated checks are **opt-in**. They require a dedicated first-party lab, a deliberately approved policy and the exact supported project adapter.

```bash
cat config/rbac.policy.example.json
cat config/auditshop.rbac.project.example.json
python -m auditor --rbac-policy config/rbac.policy.example.json --help
python tools/phase5_rbac_e2e.py
```

Do not turn `authorized_for_testing` on for a target without actual permission. Only use controlled credentials/environment variables for test accounts; never commit live passwords.

## Reporting, integrity and privacy

After a scan, open the report path printed by the CLI. The working run directory contains structured JSON data, request ledger and evidence artifacts.

Optional Phase 6 hardening commands (from the source checkout):

```bash
RUN=/path/to/a/completed/scan-directory
python tools/phase6_hardening.py --run "$RUN" --snapshot
python tools/phase6_hardening.py --run "$RUN" --verify
python tools/phase6_hardening.py --run "$RUN" --export-private ./redacted-report.html
```

Redaction is best effort; manually review HTML before sharing. A SHA-256 snapshot verifies later consistency, not provenance before the snapshot.

## Research validation and limitations

- Rules and benchmark ground truth are human/source-authored, **never AI-generated**.
- First-party synthetic lab tests are not an independent benchmark.
- Two real OWASP Benchmark Java 1.2 CHK04 detector observations were collected via a compatibility adapter: `BenchmarkTest00016` → `No Issue Observed`, `BenchmarkTest00087` POST → `Potential`.
- Human approval was still `PENDING`; the benchmark score showed **2 pending, 13 unexecuted**, not real TP/TN.
- `Potential` must be scored as **abstention**, not confirmed detection, after proper review.
- Existing CHK11 authenticated SQLi adapter is AuditShop-specific and not automatically applicable to Benchmark Java endpoints.
- The full scanner CLI was not used for that particular external CHK04 adapter experiment.
- No independently established overall precision, recall, accuracy or false-positive rate is claimed.

Relevant reproducibility tools:

```bash
python tools/phase7_evaluation.py prepare
python tools/phase7_evaluation.py verify
python tools/phase7_evaluation.py score
python tools/phase7_2_chk04.py --help
python tools/phase7_3_review.py --help
```

## Project layout

```text
auditor/    Python CLI, rules, scanning, auth, reporting, AI and evidence validation
config/     Example project configuration and approved-policy templates
docs/       Research, setup, usage and architecture documentation
lab/        Controlled local servers for validation
research/   Source mappings, benchmark labels, evaluation evidence and results
tests/      Unit, regression and localhost integration tests
tools/      Benchmark, research, provenance, review and hardening utilities
.github/    GitHub Actions CI
```

## Safety and licensing

The repository is independently developed and uses "OWASP" to describe its security-research context, **not** to imply OWASP sponsorship. No public license is assigned until code ownership and bundled third-party terms are reviewed; absence of a license generally means standard copyright rules apply. Check dependencies, original research datasets, and any borrowed code before selecting a license.

Do not commit `.env`, `.venv/`, `runs/`, real session cookies, raw authorization headers, credentials, user private evidence, or exported customer data.

## Release

Current release candidate: `0.2.0rc1`. Final Kali checks previously passed **232 tests, 41 subtests**, 13 schema-valid check records and successful wheel/sdist builds. Re-run tests after a clean clone because documentation and packaging can change.

This is a **completed research prototype**, with transparent benchmark limitations—not a security certification.
