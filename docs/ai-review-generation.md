# Automatic AI review generation

The previous context and storage stages are now connected to your configured
Ollama or HTTPS Chat Completions-compatible provider. Reviews run automatically
after existing report explanations when a scan completes or the report CLI runs.
There is no enable flag. An interrupted scan still prioritizes saved results;
regenerate its report or resume successfully to request the AI stages.

## Use the existing report command

For Windows Ollama through the current Kali SSH tunnel (adjust the port if yours differs):

```bash
.venv/bin/owasp-auditor-report --run runs/scan-YOUR_RUN_ID \
  --ai-provider ollama --ai-endpoint http://127.0.0.1:11437 --ai-model qwen3:8b
```

This sends no target requests. It generates missing summary/finding explanations,
then builds structured context, generates eligible CHK05/07/08 reviews, validates
them and updates HTML. If there are no eligible tests, reviews are not_applicable.
Old runs can be reviewed, but missing old reflection context remains unavailable.

Normal `owasp-auditor --url ...` scans use the same automatic two-stage pipeline.
Use the existing AI provider environment variables or CLI arguments. Hosted APIs
use the same selected key environment variable and HTTPS settings as report AI.

To retry only reviews without rerunning summary/finding explanations:

```bash
.venv/bin/python -m auditor.review.generate --run runs/scan-YOUR_RUN_ID \
  --ai-provider ollama --ai-endpoint http://127.0.0.1:11437 --ai-model qwen3:8b
```

No need to run context --build or store --init manually first. The generator
prepares both. The foundation commands remain available for local validation.

`--refresh-ai` on the report command regenerates both stages. On the review module
it regenerates only reviews. Review-module exit status is 1 when review generation
is incomplete and 130 on interruption; scan/report commands preserve their
existing behavior where AI failure is displayed separately from scanner success.

## What the provider receives

Only the structured, allowlisted observations, fixed limitations, rule ID and
scanner status are submitted. Evidence is named with a temporary `evidence-1`
alias; actual run/test/evidence IDs and source hashes are not sent. URLs, parameter
names/values, cookies, keys, paths and raw snippets are excluded from prompts.
Selecting a hosted provider sends this minimized metadata to that provider.

The model returns an assessment, explanation, uncertainty, evidence aliases and
one rule-specific manual-verification suggestion. Unknown aliases, extra fields,
wrong-rule suggestions, malformed/oversized/truncated JSON and duplicate JSON
keys are rejected. Valid aliases are mapped back to local evidence IDs. Source
hashes, ownership and scanner status are rechecked before an entry is saved.

No model output changes a scanner verdict or runs a command, payload or follow-up
request. A validated reference is not proof that the explanation is factually
supported. All prose remains unverified and is labelled human-review-required.
The existing schema rejects Bengali script; prompting requests English, but this
is not comprehensive language identification or semantic validation.

## Report sections and files

The HTML report now has a separate **AI review of check evidence** section.
Each entry shows scanner status, AI assessment, explanation, uncertainty, manual
verification suggestion, provider/model and evidence references. All text is
escaped. Rendering an HTML report by itself performs no provider calls.

- `results/ai.json`: existing summary/finding explanations.
- `results/ai_context.json`: rebuilt, minimized context.
- `results/ai_review.json`: validated check reviews.
- `results/ai_review_generation.json`: review-stage status, safe reason, source
  hash and generation fingerprint. No credentials are saved.

Complete means all eligible reviews were stored, not that a target is secure or
that model claims have been proven. Partial/unavailable states preserve accepted
reviews and scanner results. Context/evidence/schema failures fail closed.

## Retry, cache, archives and limits

Accepted entries are saved incrementally. Unchanged configuration, prompt,
schema and source reuse them; a later invocation retries only missing entries.
Ctrl+C during reviews retains accepted entries. Duplicate reviews are not added.

Changing provider/model/endpoint, source, prompt/schema, or forcing refresh
archives the previous structurally valid review store as
`results/ai_review.previous.<unique-id>.json` before starting fresh. Archives are
not shown as current reviews. They are retained with the run for audit/recovery;
repeated refreshes add archives. Invalid JSON/schema is never silently discarded.
Standalone store --validate still rejects stale data; the generation command is
the path that performs explicit archival and regeneration automatically.

The review stage allows at most 30 new calls and 300 seconds per invocation, with
90 seconds/request, 5 seconds connect timeout, 64 KiB response and 1100 output
tokens. Ollama uses context 4096. These are separate from the existing explanation
stage (also 30 calls/300 seconds); both together can take up to approximately ten
minutes plus local processing. Target request/time budgets are unchanged.
A local or hosted model may continue work after a client timeout.

No automatic retry loop, endpoint fallback, redirects or environment proxies are
used. Provider keys are used only for Authorization and are not included in cache
fingerprints, prompts or stored results. Updating model weights behind an
unchanged tag is not detected; refresh explicitly when needed.

## Install and verify

Install after `install_ai_context.py`. Finish paused scans first because code
fingerprints change; historical result JSON remains usable for report generation.

```bash
.venv/bin/python install_ai_review_generation.py
.venv/bin/python -m unittest discover -s tests -v
```

Installer backups: `.ai-review-generation-backups`. No scans or Git operations
are performed by installation. Tests use mock providers; they cannot establish
your real model's output quality or hosted account compatibility. Verify a saved
run using your actual provider and read the review text before relying on it.
