# AI review foundation (schema version 1)

> Integration update: the automatic generation stage is now available. See
> `ai-review-generation.md`. The local-only commands described below remain
> available; normal scans/report generation now also run AI reviews.

This step adds strict review schemas, evidence-reference validation and separate
storage. It does not call a model, send target requests, run follow-up actions,
change scanner verdicts or add review text to HTML reports. Existing automatic
English report explanations continue to use `results/ai.json` independently.
The later AI-review integration will call the APIs documented below.

## Initialize and validate

Use a saved run with valid scan, tests, findings and evidence files:

```bash
.venv/bin/python -m auditor.review.store --run runs/scan-YOUR_RUN_ID --init
.venv/bin/python -m auditor.review.store --run runs/scan-YOUR_RUN_ID --validate
```

The commands use no network; Ollama and the SSH tunnel are not needed.
`--init` creates `results/ai_review.json` with an empty reviews list. It never
fabricates AI output. Existing valid reviews are preserved. No default scan or
report command automatically creates this new store in this foundation release.

Status meanings:

- `pending`: eligible tests exist; no reviews saved yet.
- `partial`: some eligible tests have stored reviews.
- `complete`: every eligible test has a stored, structurally valid review.
- `not_applicable`: no eligible tests exist.

Complete means review storage is complete, not that the site is secure or that
AI statements were verified. Eligibility currently means CHK05, CHK07 or CHK08,
a status other than Not Tested, and at least one evidence reference. Even a
No Issue Observed test may be reviewed for scope and limitations.

## Model payload schema

Bundled schema: `auditor/reporting/schemas/ai_review.json`, definition `payload`.
A future model will produce only this object (example, not an actual AI review):

```json
{
  "assessment": "needs_human_review",
  "explanation": "A server error alone does not demonstrate SQL injection.",
  "uncertainty": "Only one malformed value was tested.",
  "evidence_refs": ["ev-EXAMPLE"],
  "suggested_verification": "review_input_handling"
}
```

Assessment enum: `consistent_with_observation`, `possible_false_positive`,
`insufficient_context`, `needs_human_review`. These are AI-review labels, not
scanner verdicts. Free-form `status`, `severity`, `command`, URL or other extra
fields are rejected. Each prose field is 1–2200 characters. Bengali script is
rejected; this is not a comprehensive language detector. English prompts and
human review remain necessary. Text is untrusted data, never executable content.

Allowed suggestions are `none` and the matching manual-review action:

| Rule | Suggestion ID |
| --- | --- |
| CHK05 | `review_error_context` |
| CHK07 | `review_reflection_context` |
| CHK08 | `review_input_handling` |

These names do not refer to executable verification modules. No action dispatcher
exists in this step. Future consumers must escape prose before displaying HTML.

## Evidence and source validation

Validation checks:

1. Source JSON satisfies existing report schemas; duplicate test/evidence IDs fail.
2. Each evidence filename matches its record ID and its canonical SHA-256 is valid.
3. Every cited ID exists and appears in the reviewed test's evidence references.
4. That evidence links back to the same test through test_id or test_ids.
5. Review metadata matches the actual test's rule and scanner status.
6. References are non-empty and unique; no duplicate reviews for a test.
7. The store matches its run ID and source snapshot hash.
8. Completion status matches the actual number of reviewed eligible tests.

Source snapshot covers parsed scan.json, tests.json, findings.json and evidence
records. Changing those inputs invalidates old review stores, including a scan
resume that changes saved results. Formatting-only JSON changes do not invalidate
it. Missing/malformed/stale stores are never silently replaced. Archive a stale
store explicitly before initializing one for changed results. Initialize reviews
on a finished run when possible.

Hash checks detect inconsistent content, not cryptographic authenticity. A local
actor able to edit both data and hashes can forge records. Reference validation
does not prove that an AI explanation is supported semantically by the evidence.
No reviewer label certifies a vulnerability. Metadata is not proof of a model call.

## Integration API (for the next step)

```python
from auditor.review.store import initialize, load_reviews, save_review

state = initialize(run_directory)
# payload will come from a future provider call, not from this storage module.
state = save_review(
    run_directory,
    selected_test_id,
    validated_model_payload,
    provider="ollama",
    model="qwen3:8b",
)
state = load_reviews(run_directory)
```

The caller binds the test ID and provider/model from trusted invocation context.
The model cannot set those envelope fields. The store derives scanner_status,
rule_id, timestamp and review_required=true. Saving again for one test replaces
that review without creating duplicates. Other reviews are retained.

The same per-run lock used by scanning protects review reads and writes. Stores
are bounded to 4 MiB and 1000 entries; writes use atomic replacement. Invalid
updates and failed writes preserve the previous store. The source files,
scanner findings, report AI cache and existing HTML report are not modified.
No API key is required or accepted by these storage functions.

## Installation and testing

Install after the check-selection update. Finish paused scans before upgrading:
new Python modules change the code fingerprint. Old saved result files can
still be initialized and validated without resuming their scan checkpoints.

```bash
.venv/bin/python install_ai_review_foundation.py
.venv/bin/python -m unittest discover -s tests -v
```

The installer backs up changed files under `.ai-review-backups` and performs no
scan, network request or Git operation. It does not initialize run data for you.
The schema is included by the existing package-data rule in wheel builds.

Tests cover valid storage, source preservation, unknown/unrelated evidence,
backlink and hash mismatch, extra fields, bounded prose, duplicate IDs, stale
source, partial/completion accounting, corrupt JSON, lock contention, symlink
rejection and atomic-write failure. They do not establish model quality.
