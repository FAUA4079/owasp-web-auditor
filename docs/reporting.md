# Offline report and JSON validation

Install report dependencies with the project's virtual environment:

    .venv/bin/python -m pip install -r requirements-report.txt

Normal scans and resume exports now render the bundled Jinja template automatically.
To regenerate a report from saved JSON, without any network requests:

    .venv/bin/python -m auditor.reporting.html_report --run runs/scan-ID

To validate the report inputs separately:

    .venv/bin/python -m auditor.reporting.validation --run runs/scan-ID

Schema version 1 checks scan metadata, tests, grouped findings, evidence, and
coverage/integrity if present. Required fields, types, counters and outcome
values are checked. Additional fields are allowed for compatibility. Missing
coverage/integrity in older runs is displayed as unavailable. Invalid files
are rejected; validation does not silently coerce data. This is not a schema
for checkpoints, discovery inventory, plans, raw findings or request ledgers.
Use the existing integrity audit for references, hashes and request accounting.
Neither validator establishes vulnerability validity or complete coverage.

The HTML report includes outcome counts, grouped findings, tests, evidence,
coverage and session history. It loads no external scripts, fonts or images.
Target values are escaped and never interpreted as Jinja source. Reports can
be opened directly in Firefox; evidence panels can be expanded. Rendering
validates before writing and uses an atomic replacement, preserving an existing
report on validation failure. Report-only generation does not modify saved JSON.

Finish paused scans before upgrading: changing auditor Python code changes the
resume fingerprint, so old checkpoints cannot resume under the new version.
Saved result JSON can still be used to regenerate compatible historical reports.

The installer backs up replaced files under .report-backups and records which
files did not previously exist in __installation__.json within the backup ZIP.
For manual rollback, restore the backed-up files to their original relative
paths and remove only the new files listed in that manifest. Do not restore
while a scanner is running. Dependencies are not uninstalled by rollback.
