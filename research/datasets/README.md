# External research data staging

This directory intentionally contains no synthetic OWASP/ASVS/CWE source data. Use `python tools/research_dataset.py fetch-asvs` on Kali to retrieve the official ASVS 5.0.0 CSV and generate a local receipt with its SHA-256. For the MITRE CWE 5.0 export, download from the official MITRE download page, then `python tools/research_dataset.py import-cwe /path/to/download.zip`. Downloads stay in `research/datasets/external/` (excluded from source release). Check CSV headers/record counts and license before assigning exact requirement identifiers.

A SHA-256 receipt proves which bytes were downloaded, not that their semantic interpretation or source is trustworthy. The canonical project contains metadata and a verified importer only, no AI generated labels.
