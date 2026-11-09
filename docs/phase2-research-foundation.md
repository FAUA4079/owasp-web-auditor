# Phase 2: Versioned research foundation (initial implementation)

Date: 2026-11-08

## Key distinction

`research/chk01_chk12_traceability.csv` is a *methodology traceability artifact*, not empirical validation. Each relationship is explicitly marked direct, related, preliminary step, or no exact scenario. The registry's OWASP Top 10 categories were copied from the existing code, **not independently certified** here. The CSV contains no ASVS requirement numbers or CWE mapping numbers because official machine-readable datasets were not ingested in this runtime; do not fabricate IDs.

## Versioned sources

- WSTG v4.2: https://wstg.owasp.org/v4.2/ (use versioned `WSTG-v42-*` identifiers)
- ASVS v5.0.0 stable: https://asvs.owasp.org/downloads/ (official download link in manifest)
- MITRE CWE v5.0: https://cwe.mitre.org/data/downloads
- OWASP Top 10:2025: https://top10.owasp.org/2025/

Official source material is **not bundled**. Their URLs and publisher/release version were checked against project pages. Web-page research is human-reviewed; individual WSTG pages were checked for the strongest direct mappings. Other references are labeled related/incomplete instead of overstating coverage.

## Import official dataset bytes on Kali

```
python tools/research_dataset.py verify-matrix
python tools/research_dataset.py fetch-asvs
# Download an appropriate CWE 5.0 CSV/XML export directly from https://cwe.mitre.org/data/downloads
python tools/research_dataset.py import-cwe ~/Downloads/<official-cwe-export>.zip
python tools/research_dataset.py verify-receipts
python -m pytest -q
```

The importer keeps external downloaded bytes outside the bundled source (`research/datasets/external/` ignored by Git). It generates a receipt with SHA-256 and byte count, not an asserted pre-known checksum. Verify any publisher-supplied hashes and license separately before redistribution. Do not use a generated receipt as independent proof of publisher authenticity. A downloaded CWE file's version must be manually verified; the importer does not infer it from content.

## Next review gates

1. Parse imported ASVS CSV and independently confirm each exact requirement before filling `asvs_exact_requirement`.
2. Check official CWE 5.0 primary XML/CSV descriptions and map only precise weakness codes, not guessed synonyms.
3. Build licensed, labeled positive/negative lab scenarios per CHK; keep expected truth separate from observed scanner output.
4. Run checks against authorized local AuditShop and controlled non-production targets; calculate TP/FP/FN/TN with skip counts separately.
5. Have reviewer sign off each candidate mapping before it is promoted to `verified` status.

No new vulnerability detection rules or AI-generated test records are included in Phase 2.
