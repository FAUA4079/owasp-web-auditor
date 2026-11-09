# Automatic AI reporting

AI explanations run automatically after durable scan results are saved. The
report includes an English summary and English explanations for grouped findings.
No enable flag is required. Choose local Ollama or an HTTPS API compatible with
Chat Completions. AI never changes the scanner's verdict, severity or evidence.

## Provider configuration

Command options take precedence over environment variables. Environment variables
apply to the current shell and child processes; they are not saved in checkpoints.
Use the same configuration when regenerating reports or resuming scans.

| Command option | Environment variable | Default |
| --- | --- | --- |
| `--ai-provider` | `OWA_AI_PROVIDER` | `ollama` |
| `--ai-endpoint` | `OWA_AI_ENDPOINT` | `http://127.0.0.1:11434` for Ollama; required for hosted API |
| `--ai-model` | `OWA_AI_MODEL` | `qwen3:8b` for Ollama; required for hosted API |
| `--ai-key-env` | `OWA_AI_KEY_ENV` | `OWA_AI_API_KEY` |

The API key is the VALUE of the selected environment variable. There is no
command-line option accepting the key itself. Never include a key in the endpoint.
Old `OWA_AI_LANGUAGE` settings are ignored; explanations are English only.
The template, messages and documentation are English. Original target URLs,
evidence and user-supplied source data are preserved rather than translated.

These options work with `owasp-auditor`, `python -m auditor`, scan resume, and
`owasp-auditor-report`. `--refresh-ai` is available on the report command.

## Local Ollama (no API key)

For Ollama on the same Linux machine, defaults use port 11434:

```bash
export OWA_AI_PROVIDER=ollama
export OWA_AI_ENDPOINT=http://127.0.0.1:11434
export OWA_AI_MODEL=qwen3:8b
.venv/bin/owasp-auditor --url http://127.0.0.1:8001/discovery.html
```

For the existing Windows-to-Kali SSH tunnel, use port 11436 on Kali instead:

```bash
export OWA_AI_PROVIDER=ollama
export OWA_AI_ENDPOINT=http://127.0.0.1:11436
export OWA_AI_MODEL=qwen3:8b
.venv/bin/owasp-auditor-report --run runs/scan-YOUR_RUN_ID --refresh-ai
```

Keep Ollama and the Windows SSH tunnel running. The model must be installed
already. Local endpoints accept only HTTP on literal 127.0.0.1 and an explicit
port. The tool does not download models. Ollama never receives the API key even
if an API-key variable exists in the environment.

## Hosted API (your own key)

Requirements: HTTPS base URL, model ID enabled for your account, Bearer API key,
`POST /chat/completions`, JSON object output, and a model accepting `max_tokens`.
This is an OpenAI-compatible protocol adapter, not support for every provider's
native API. Incompatible models return an unavailable AI status. There is no
silent provider fallback and no built-in shared key. Provider pricing and rate
limits apply; free access is not guaranteed.

Example with Groq's compatible endpoint (select a supported model from your account):

```bash
export OWA_AI_PROVIDER=openai-compatible
export OWA_AI_ENDPOINT=https://api.groq.com/openai/v1
read -r 'OWA_AI_MODEL?Model ID: '
export OWA_AI_MODEL
read -rs 'OWA_AI_API_KEY?API key: '
printf '\n'
export OWA_AI_API_KEY
.venv/bin/owasp-auditor-report --run runs/scan-YOUR_RUN_ID --refresh-ai
```

The `read` examples above use Kali's default zsh. In bash use:

```bash
read -r -p 'Model ID: ' OWA_AI_MODEL
export OWA_AI_MODEL
read -r -s -p 'API key: ' OWA_AI_API_KEY
printf '\n'
export OWA_AI_API_KEY
```

The hidden prompt avoids writing the secret into shell history. Do not paste a
key into a command argument. To use an existing provider key variable instead:

```bash
.venv/bin/owasp-auditor --url http://127.0.0.1:8001/discovery.html \
  --ai-provider openai-compatible \
  --ai-endpoint https://api.groq.com/openai/v1 \
  --ai-model YOUR_MODEL_ID \
  --ai-key-env GROQ_API_KEY
```

`GROQ_API_KEY` must already be exported. The endpoint is the API base URL,
including its version path, not the full `/chat/completions` URL.
The same arguments work with `--resume runs/scan-YOUR_RUN_ID`.
Unset the secret when finished: `unset OWA_AI_API_KEY` (or your selected variable).
The tool does not automatically load `.env` files. `.env.example` documents
non-secret settings only; use environment variables or a trusted secret manager.

## Data handling

Selecting a hosted provider sends minimized scan metadata to that provider.
Only fixed rule descriptions, outcomes, severity labels, counts, and allowlisted
boolean/integer observations are sent. URLs, hostnames, paths, raw response
bodies/headers, cookies, account credentials, parameter names/values and arbitrary
evidence text are omitted. This is minimization, not a universal secret scanner.

Keys are used only in the API Authorization header. They are excluded from
prompts, cache fingerprints, result JSON and reports. Raw provider errors and
responses are not logged. Redirects and environment proxies are disabled;
HTTPS certificate verification remains enabled. Only use an endpoint you trust
with that provider's key. Keys stay in process memory while needed.

Model output must contain exactly four bounded JSON strings: `explanation`,
`limitations`, `suggested_fix`, `retest`. Invalid, truncated and oversized output
is rejected. Bengali-script output is rejected; the English instruction is not
a comprehensive language detector. Factual accuracy is not guaranteed. AI text
is escaped, never executed, and marked as requiring human review.

## Reports, caching and failure handling

`results/ai.json` stores provider/model/language, explanations, generation status,
cache fingerprints and a source hash. Changed source results, provider settings,
model or prompt invalidate the relevant cache. This upgrade hides old-language
AI caches until regeneration. Existing HTML files change only when regenerated.
Use `--refresh-ai` after a provider changes model content behind the same model ID.

A normal or budget-stopped scan attempts AI after saving the base report.
An interrupted/crashed scan preserves partial scanner results and defers AI.
Report regeneration and completed-run resume can finish missing AI without
rescanning the target. Completed explanations are saved incrementally.

If AI fails, the scanner's report remains available, showing AI as partial or
unavailable and a safe reason. It is never labelled complete when AI is missing.
Scan success is independent of AI success. Typical reasons:

| Reason | Action |
| --- | --- |
| `missing_or_invalid_api_key` | Export the selected key variable |
| `api_authentication_failed` | Check or replace the key |
| `api_access_denied` | Check account/model permissions |
| `api_rate_limited` | Wait and check provider quota |
| `model_connection_error` | Check endpoint, local model or SSH tunnel |
| `model_http_error` | Check base URL and model/API compatibility |
| `invalid_model_output` | Retry or select a compatible model |
| `incomplete_model_output` | Output was truncated/refused; choose a suitable model |

No automatic retries or provider switching are performed. Limits per invocation:
30 new entries, 300 seconds total, 90 seconds per request, 5 seconds connection,
64 KiB response body, 1100 output tokens. Ollama uses context 4096. Rerun the
report command to finish pending items. AI calls do not consume target request
budgets. Ctrl+C saves completed explanations for a later retry.

## Upgrade and validation

Finish paused scans before upgrading; code changes invalidate old resume
fingerprints. Saved result JSON can still be used to regenerate historical reports.
Installer backups are stored in `.ai-provider-backups`; the backup manifest lists
new files. Installation performs no scans or Git operations.

Tests use mock HTTP responses; a passing suite does not verify a live provider
account or model prose quality. Verify one report with your own setup.

References: https://console.groq.com/docs/api-reference and
https://docs.ollama.com/api/chat

## Automatic evidence review stage

After summary/finding explanations, the tool now generates separately validated
CHK05/07/08 reviews automatically. `--refresh-ai` refreshes both stages. See
`ai-review-generation.md` for review files, archival, privacy and additional
request/time limits.
