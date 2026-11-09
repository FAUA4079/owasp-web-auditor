# Structured AI review context

> Integration update: the automatic generation stage is now available. See
> `ai-review-generation.md`. The local-only commands described below remain
> available; normal scans/report generation now also run AI reviews.

This stage prepares minimized input for future AI review of CHK05, CHK07 and
CHK08. It does not call a model, run a follow-up test or change a scanner verdict.
Existing automatic AI report explanations continue independently.

## Build from saved evidence

After installing the AI review foundation and this update:

```bash
.venv/bin/python -m auditor.review.context --run runs/scan-YOUR_RUN_ID --build
.venv/bin/python -m auditor.review.context --run runs/scan-YOUR_RUN_ID --validate
```

Output: `results/ai_context.json`. These commands need neither an active target
server nor Ollama nor an SSH tunnel. They read saved evidence only. Building is
explicit in this release; existing scan/report commands do not automatically
build this file yet. New CHK07 scans automatically capture reflection labels.

`ready` means context was prepared for eligible tests; it does not mean an AI
review was generated or a security issue was confirmed. `not_applicable` means
there are no eligible CHK05/07/08 tests. Not Tested records are excluded.

## Included observations

| Rule | Context |
| --- | --- |
| CHK05 | HTTP status, supported signature type names, availability and inspection-limit flags |
| CHK07 | Baseline/probe statuses, exact marker presence, stopped flag, bounded parser context labels |
| CHK08 | Baseline/probe statuses, supported baseline/probe error types, their set difference, inspection support and stopped flags |

All entries contain test ID, rule ID, scanner status, one evidence reference and
fixed limitations. Only enumerated type names and typed boolean/numeric metadata
are projected. Invalid/missing scalar data becomes null; malformed reflection
metadata becomes unavailable. New error types are derived from allowlisted
baseline/probe types, not copied from arbitrary text in a stored field.

Target URLs, hostname, parameter names/values, credentials, cookies, response
bodies, raw headers, error messages, paths, excerpts, arbitrary source titles and
reasons are omitted. No raw snippets are included. A source hash is retained for
local provenance; this foundation sends nothing to a provider. These are narrow
projections, not a claim of universal secret redaction. IDs and hashes should
remain local unless a later integration explicitly needs them.

## New CHK07 reflection metadata

CHK07 rule version is now 0.2.0. Its verdict logic and request count are unchanged.
After a comparable successful baseline/probe pair, it classifies a bounded
UTF-8-decoded probe prefix and records labels such as:

- html_text / html_attribute
- script_text / style_text
- html_comment / plain_text
- attribute_name / tag_name / unclassified

The helper inspects at most 200,000 decoded characters (bounded byte decoding)
and caps the occurrence counter at 20. It retains neither marker nor text nor
attribute names/values. Multiple labels may be present. Inspection and count
limits are explicit. The source HTTP client retains its existing response cap.

Python HTMLParser is heuristic, including for XHTML, malformed markup, browser
raw-text rules, entity decoding and non-UTF-8 encodings. Labels are not an exact
browser DOM or JavaScript grammar analysis. A script_text label does not prove
JavaScript execution. Output encoding safety, stored/transformed reflection and
browser execution remain untested. Marker presence outside the inspected prefix
can coexist with no classified context; the inspection limit explains that gap.

Old CHK07 runs do not contain this metadata. They show context state unavailable
rather than guessing. Run a new authorized scan to capture it; rebuilding context
from an old run cannot recover a response body that was not saved.

## What remains unknown

CHK05 cannot decide whether a traceback is a live backend error or an example in
documentation using the stored metadata. runtime_origin remains not_determined.
CHK08 does not contain a complete body comparison; full_response_comparison is
not_available. A 5xx response remains insufficient proof of SQL injection/outage.

## Validation and storage

The builder reuses the foundation's source-schema, evidence-hash and ownership
validation. Each projected test must have exactly one evidence record and its
observed object must match that evidence's observation. Inconsistency aborts the
build without modifying the existing context. All output follows the bundled
strict ai_context.json schema.

The store uses the scan lock, size limits and atomic replacement. Validation
recomputes the projection from current evidence and rejects stale/altered context.
`--build` explicitly replaces derived context with a fresh projection. It does
not modify source JSON, the HTML report, results/ai.json or results/ai_review.json.
A stale review store is still rejected by the separate review validator; rebuilding
context does not make an old AI review valid again.

## Installation and tests

Finish paused scans before installation; Python changes alter resume fingerprints.
Old saved results remain usable for context building without resuming checkpoints.

```bash
.venv/bin/python install_ai_context.py
.venv/bin/python -m unittest discover -s tests -v
```

The installer expects the preceding AI-review-foundation version, checks source
compatibility, and creates .ai-context-backups. It performs no scans or Git actions.
The schema is covered by the existing wheel package-data rule.

Tests cover projection privacy, source/evidence consistency, legacy missing data,
reflection labels, parser limits, stale context, failed atomic writes, symlinks,
and capture through the actual CHK07 function without extra requests.
Next stage: provider-backed review generation using this input and the existing
review schema, followed by separately rendered AI review sections.
