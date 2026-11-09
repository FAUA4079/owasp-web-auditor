#!/usr/bin/env python3
"""Phase 7: independently sourced labels, strict applicability and fail-closed scoring.

This is an offline evidence tool, not a scanner. External labels remain UNEXECUTED
until the actual benchmark server is locally installed and scanner evidence imported.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / 'research/phase7/external/owasp_benchmark_java_1_2_verified_subset.csv'
DEFAULT_MAP = ROOT / 'research/phase2_exact_mapping.csv'
OUT = ROOT / 'research/phase7'
SOURCE_URL = 'https://github.com/OWASP-Benchmark/BenchmarkJava/blob/master/expectedresults-1.2.csv'
STATUS_ALLOWED = {'Confirmed', 'Potential', 'No Issue Observed', 'Inconclusive', 'Not Tested'}
ID_RE = re.compile(r'BenchmarkTest\d{5}$')

class EvaluationError(ValueError):
    pass

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def json_save(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')

def load_labels(path: Path) -> list[dict]:
    text = path.read_text(encoding='utf-8')
    lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    seen = set()
    result = []
    for row in csv.reader(lines, strict=True):
        if len(row) != 4:
            raise EvaluationError('Expected four columns in external benchmark CSV')
        test_id, category, vulnerable, cwe = [x.strip() for x in row]
        if not ID_RE.fullmatch(test_id) or test_id in seen:
            raise EvaluationError('Invalid or duplicate external test ID')
        if vulnerable.lower() not in {'true', 'false'} or not cwe.isdecimal():
            raise EvaluationError('Invalid label or CWE')
        if (category, cwe) not in {('securecookie', '614'), ('sqli', '89')}:
            raise EvaluationError('Unreviewed category/CWE pair')
        seen.add(test_id)
        result.append({'case_id': test_id, 'category': category, 'cwe': f'CWE-{cwe}',
                       'expected_vulnerability': vulnerable.lower() == 'true',
                       'check_id': 'CHK04' if category == 'securecookie' else 'CHK11',
                       'source': 'OWASP Benchmark Java v1.2 author labels'})
    if not result:
        raise EvaluationError('No external labels')
    return result

def read_mapping(path: Path) -> dict:
    with path.open(newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    lookup = {r['chk_id']: r for r in rows}
    expected = {f'CHK{i:02d}' for i in range(1, 14)}
    if set(lookup) != expected:
        raise EvaluationError('Mapping must contain all CHK01–CHK13 once')
    return lookup

def prepare(data: Path, mapping: Path, target: Path) -> dict:
    labels = load_labels(data)
    known = read_mapping(mapping)
    coverage = []
    for i in range(1, 14):
        chk = f'CHK{i:02d}'
        r = known[chk]
        candidates = [c['case_id'] for c in labels if c['check_id'] == chk]
        coverage.append({'check_id': chk, 'asvs_ids': r['asvs_v5_req_ids'].split(';') if r['asvs_v5_req_ids'] else [],
                         'cwe_ids': r['cwe_v5_ids'].split(';') if r['cwe_v5_ids'] else [],
                         'external_cases': candidates, 'case_count': len(candidates),
                         'suitability': ('CWE-level candidate, requires independent endpoint and detector compatibility review'
                                         if candidates else 'No benchmark case selected for a directly compatible check'),
                         'execution_status': 'UNEXECUTED'})
    manifest = {'schema_version': 1, 'dataset_name': 'OWASP BenchmarkJava expectedresults-1.2.csv',
                'source_url': SOURCE_URL, 'source_release': '1.2',
                'source_commit_pinned': False, 'full_original_file_bundled': False,
                'subset_provenance': 'Rows transcribed verbatim from upstream GitHub CSV; full source not vendored',
                'subset_sha256': digest(data), 'mapping_sha256': digest(mapping),
                'review_sheet_sha256': digest(OUT / 'human_label_review.csv'),
                'review_status': 'SOURCE_AUTHORED_NOT_INDEPENDENTLY_HUMAN_SIGNED_OFF',
                'labels_count': len(labels), 'labels': labels, 'applicability': coverage,
                'limitations': ['No external benchmark application executed',
                                'CHK11 AuditShop SQL differential incompatible with BenchmarkJava servlet interface',
                                'CHK04 cookie attributes not a case-level CWE-614 finding without endpoint correlation',
                                'No signed human reviewer approval or independent duplicate label check',
                                'CWE matching alone does not establish detector applicability']}
    json_save(target, manifest)
    return manifest

def score(manifest_path: Path, observations_path: Path | None = None, artifacts_root: Path | None = None) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    source_file = DEFAULT_DATA
    mapping_file = DEFAULT_MAP
    if (manifest.get('subset_sha256') != digest(source_file) or
            manifest.get('mapping_sha256') != digest(mapping_file) or
            manifest.get('review_sheet_sha256') != digest(OUT / 'human_label_review.csv')):
        raise EvaluationError('Provenance SHA-256 mismatch: refusing to score')
    current_labels = load_labels(source_file)
    if manifest.get('labels') != current_labels:
        raise EvaluationError('Labels differ from source file')
    obs = {}
    if observations_path is not None:
        raw = json.loads(observations_path.read_text(encoding='utf-8'))
        if not isinstance(raw, dict) or raw.get('schema_version') != 1 or not isinstance(raw.get('observations'), list):
            raise EvaluationError('Invalid observations schema')
        if artifacts_root is None:
            raise EvaluationError('Evidence root required for external observations')
        root = artifacts_root.resolve(strict=True)
        for item in raw['observations']:
            key = item.get('case_id')
            if key in obs or key not in {c['case_id'] for c in current_labels}:
                raise EvaluationError('Unknown or duplicate case observation')
            if item.get('status') not in STATUS_ALLOWED or item.get('check_id') not in {'CHK04', 'CHK11'}:
                raise EvaluationError('Invalid check or status')
            if not re.fullmatch('[0-9a-f]{64}', str(item.get('evidence_sha256', ''))):
                raise EvaluationError('Observations require verifiable evidence SHA-256')
            if not item.get('human_review_reference') or not item.get('benchmark_endpoint'):
                raise EvaluationError('Observations require review reference and endpoint identity')
            rel = item.get('evidence_path')
            if not isinstance(rel, str) or not rel or Path(rel).is_absolute():
                raise EvaluationError('Evidence requires a relative file path')
            resolved = (root / rel).resolve(strict=True)
            if not resolved.is_relative_to(root) or not resolved.is_file() or digest(resolved) != item['evidence_sha256']:
                raise EvaluationError('Missing, escaped, or mismatched evidence artifact')
            obs[key] = item
    counters = Counter()
    by_check = defaultdict(Counter)
    cases = []
    for label in current_labels:
        item = obs.get(label['case_id'])
        if item and item['check_id'] != label['check_id']:
            raise EvaluationError('Observation check does not match applicability map')
        if not item:
            outcome = 'UNEXECUTED'
        elif item['status'] in {'Inconclusive', 'Not Tested', 'Potential'}:
            outcome = 'ABSTAINED'
        elif item['status'] == 'Confirmed':
            outcome = 'TP' if label['expected_vulnerability'] else 'FP'
        elif item['status'] == 'No Issue Observed':
            outcome = 'FN' if label['expected_vulnerability'] else 'TN'
        counters[outcome] += 1
        by_check[label['check_id']][outcome] += 1
        cases.append({**label, 'outcome': outcome, 'observation_status': item['status'] if item else None})
    tp, fp, tn, fn = [counters[k] for k in ('TP', 'FP', 'TN', 'FN')]
    def fraction(a, b):
        return round(a / b, 6) if b else None
    return {'schema_version': 1, 'dataset': manifest['dataset_name'], 'manifest_sha256': digest(manifest_path),
            'execution_mode': 'external_evidence_only', 'external_labels_total': len(cases),
            'counts': {k: counters[k] for k in ('TP', 'FP', 'TN', 'FN', 'ABSTAINED', 'UNEXECUTED')},
            'metrics': {'precision': fraction(tp, tp + fp), 'recall': fraction(tp, tp + fn),
                        'false_positive_rate': fraction(fp, fp + tn),
                        'scored_fraction': fraction(tp + fp + tn + fn, len(cases)),
                        'execution_fraction': fraction(len(cases) - counters['UNEXECUTED'], len(cases))},
            'per_check': {chk: {k: by_check[chk][k] for k in ('TP', 'FP', 'TN', 'FN', 'ABSTAINED', 'UNEXECUTED')} for chk in ('CHK04', 'CHK11')},
            'cases': cases,
            'cautions': ['Missing observations are UNEXECUTED, never auto-classified as FN',
                         'Potential is abstention: not proof of a benchmark vulnerability',
                         'Externally published source labels are not equivalent to human sign-off',
                         'Evidence digest input must be independently checked against preserved artifact before use']}

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['prepare', 'score', 'verify'])
    p.add_argument('--dataset', type=Path, default=DEFAULT_DATA)
    p.add_argument('--mapping', type=Path, default=DEFAULT_MAP)
    p.add_argument('--manifest', type=Path, default=OUT / 'external_manifest.json')
    p.add_argument('--observations', type=Path)
    p.add_argument('--artifacts-root', type=Path, help='Required when scoring observations; verifies evidence bytes')
    p.add_argument('--output', type=Path, default=OUT / 'external_score.json')
    args = p.parse_args()
    try:
        if args.action == 'prepare':
            result = prepare(args.dataset, args.mapping, args.manifest)
            print(f"PASS: provenance manifest prepared for {result['labels_count']} source-authored cases; 0 externally executed")
        elif args.action == 'verify':
            score(args.manifest)
            print('PASS: source subset/mapping SHA-256 and label membership unchanged')
        else:
            result = score(args.manifest, args.observations, args.artifacts_root)
            json_save(args.output, result)
            print(json.dumps({'counts': result['counts'], 'metrics': result['metrics']}))
    except (EvaluationError, FileNotFoundError, ValueError) as exc:
        p.exit(2, f'FAIL: {exc}\n')

if __name__ == '__main__':
    main()
