#!/usr/bin/env python3
"""Phase 7.2: bounded localhost OWASP Benchmark CHK04 adapter.

Uses the existing auditor.checks.cookies.review_cookies function UNCHANGED.
Network collection is explicitly opt-in, localhost-only, and requires Docker source
attestation. Offline scoring is gated by independent human review.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from auditor.checks.cookies import review_cookies

ROOT = Path(__file__).resolve().parents[1]
CHK04_FILE = ROOT / 'auditor/checks/cookies.py'
PINNED_COMMIT = '00bcf97075c409b6762d343496e75046b6a64716'
PINNED_CSV_SHA256 = '1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1'
BASE = 'https://127.0.0.1:8443'
CASES = {
    'BenchmarkTest00016': {'path': '/benchmark/securecookie-00/BenchmarkTest00016', 'expected': False, 'method': 'GET'},
    'BenchmarkTest00087': {'path': '/benchmark/securecookie-00/BenchmarkTest00087', 'expected': True, 'method': 'POST'},
}
HEX = re.compile(r'^[0-9a-f]{64}$')

class EvaluationError(ValueError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def filehash(path: Path) -> str:
    return sha(path.read_bytes())


def save_json(path: Path, obj: object, sensitive: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never leave raw Set-Cookie data world-readable.
    data = (json.dumps(obj, indent=2, sort_keys=True) + '\n').encode('utf-8')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if sensitive else 0o644)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    except BaseException:
        os.close(fd) if fd >= 0 else None
        raise


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise EvaluationError(f'Invalid object: {path}')
    return value


def check_local_base(base: str) -> str:
    p = urlsplit(base)
    if p.scheme != 'https' or p.hostname != '127.0.0.1' or p.port != 8443 or p.path not in ('', '/') or p.query or p.fragment or p.username or p.password:
        raise EvaluationError('Only https://127.0.0.1:8443 is authorized; no remote targets')
    return BASE


def docker_output(docker: list[str], args: list[str]) -> str:
    proc = subprocess.run(docker + args, check=False, capture_output=True, text=True, timeout=35)
    if proc.returncode:
        raise EvaluationError('Docker verification failed: ' + proc.stderr.strip()[:500])
    return proc.stdout.strip()


def verify_container(docker: list[str], container: str) -> dict:
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}', container):
        raise EvaluationError('Invalid container name')
    container_id = docker_output(docker, ['inspect', '--format', '{{.Id}}', container])
    image_id = docker_output(docker, ['inspect', '--format', '{{.Image}}', container])
    commit = docker_output(docker, ['exec', container, 'git', '-C', '/owasp/BenchmarkJava', 'rev-parse', 'HEAD'])
    dirty = docker_output(docker, ['exec', container, 'git', '-C', '/owasp/BenchmarkJava', 'status', '--porcelain'])
    source_csv = docker_output(docker, ['exec', container, 'sha256sum', '/owasp/BenchmarkJava/expectedresults-1.2.csv']).split()[0]
    if commit != PINNED_COMMIT or dirty:
        raise EvaluationError('Source commit mismatch or working tree dirty; refuse live collection')
    if source_csv != PINNED_CSV_SHA256:
        raise EvaluationError('Benchmark expected-results CSV SHA-256 mismatch')
    return {'container_id': container_id, 'image_id': image_id, 'commit': commit, 'csv_sha256': source_csv, 'working_tree_clean': True}


def source_labels_from_csv(content: str) -> dict:
    labels = {}
    for row in csv.reader(line for line in content.splitlines() if line.strip() and not line.startswith('#')):
        if len(row) != 4:
            raise EvaluationError('Unexpected benchmark CSV row')
        case_id, category, expected, cwe = (x.strip() for x in row)
        if case_id in CASES:
            if case_id in labels or (category, cwe) != ('securecookie', '614') or expected not in ('true', 'false'):
                raise EvaluationError('Incorrect benchmark label/category/CWE')
            labels[case_id] = expected == 'true'
    if set(labels) != set(CASES) or any(labels[k] != v['expected'] for k, v in CASES.items()):
        raise EvaluationError('Source labels do not match pinned expectation')
    return labels


def capture_evidence(method: str, url: str, response: httpx.Response) -> dict:
    """Preserve response headers for later replay through actual CHK04.

    Does not record request cookies, request body, or response body.
    """
    return {
        'schema_version': 1,
        'method': method, 'url': url,
        'http_status': response.status_code,
        'response_headers': [[k.decode('latin-1'), v.decode('latin-1')] for k, v in response.headers.raw],
        'body_sha256': sha(response.content), 'body_length': len(response.content),
        'captured_at': datetime.now(timezone.utc).isoformat(),
        'origin': 'live_httpx_localhost_benchmark',
    }


def evaluate_evidence(evidence: dict) -> dict:
    headers = evidence.get('response_headers')
    if not isinstance(headers, list) or not all(isinstance(v, list) and len(v) == 2 and all(isinstance(x, str) for x in v) for v in headers):
        raise EvaluationError('Invalid raw header evidence')
    url = evidence.get('url')
    method = evidence.get('method')
    if not isinstance(url, str) or not isinstance(method, str) or (method, url) not in {
        (v['method'], BASE + v['path']) for v in CASES.values()
    }:
        raise EvaluationError('Unapproved method or endpoint')
    status = evidence.get('http_status')
    if status != 200:
        raise EvaluationError('Benchmark servlet did not return HTTP 200')
    # Invoke EXACT original CHK04 detector, not a benchmark-custom replacement.
    test, audit_evidence, findings = review_cookies({
        'headers': httpx.Headers(headers), 'final_url': url, 'status_code': status,
    })
    return {'check_id': 'CHK04', 'status': test['status'], 'reason': test['reason'],
            'observed': test['observed'], 'finding_count': len(findings),
            'detector_sha256': filehash(CHK04_FILE), 'detector_entrypoint': 'auditor.checks.cookies.review_cookies'}


def capture(root: Path, docker: list[str], container: str, base: str, client=None) -> dict:
    check_local_base(base)
    if root.exists() and any(root.iterdir()):
        raise EvaluationError('Output directory must be empty: preserve previous evidence')
    attestation = verify_container(docker, container)
    # Get unmodified source file from the same running container (not latest GitHub).
    raw_csv = subprocess.run(docker + ['exec', container, 'cat', '/owasp/BenchmarkJava/expectedresults-1.2.csv'],
                             capture_output=True, timeout=35, check=True).stdout
    if sha(raw_csv) != PINNED_CSV_SHA256:
        raise EvaluationError('Source CSV bytes do not match pinned digest')
    source_labels_from_csv(raw_csv.decode('utf-8'))
    root.mkdir(parents=True, exist_ok=False) if not root.exists() else None
    csv_path = root / 'source_expectedresults-1.2.csv'
    csv_path.write_bytes(raw_csv)
    generated = []
    own_client = client is None
    if own_client:
        client = httpx.Client(verify=False, follow_redirects=False, timeout=15.0, trust_env=False)
    try:
        for case, info in CASES.items():
            url = base + info['path']
            if info['method'] == 'GET':
                response = client.get(url, headers={case: 'phase7-controlled-test'})
            else:
                # The vulnerable servlet requires GET to issue its seed cookie.
                setup = client.get(url)
                if setup.status_code != 200:
                    raise EvaluationError('Benchmark case setup GET did not return HTTP 200')
                cookie = httpx.Cookies()
                # Copy only the exact benchmark seed cookie, never arbitrary cookies.
                from http.cookies import SimpleCookie
                for raw in setup.headers.get_list('set-cookie'):
                    parsed = SimpleCookie()
                    parsed.load(raw)
                    if case in parsed:
                        cookie.set(case, parsed[case].value)
                if case not in cookie:
                    raise EvaluationError('Benchmark seed cookie missing in setup GET')
                response = client.post(url, cookies=cookie)
            evidence = capture_evidence(info['method'], url, response)
            prediction = evaluate_evidence(evidence)
            filename = f'{case}.http-evidence.json'
            save_json(root / filename, evidence, sensitive=True)
            generated.append({'case_id': case, 'check_id': 'CHK04', 'method': info['method'],
                              'endpoint': url, 'evidence_path': filename, 'evidence_sha256': filehash(root / filename),
                              'prediction': prediction, 'source_expected_vulnerability': info['expected']})
    finally:
        if own_client:
            client.close()
    review_csv = root / 'human_review.csv'
    with review_csv.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['case_id', 'review_status', 'reviewer', 'review_reference', 'notes'])
        for case in CASES:
            writer.writerow([case, 'PENDING', '', '', 'Verify exact servlet/method, observed Set-Cookie, and source label independently'])
    manifest = {'schema_version': 1, 'phase': '7.2', 'execution_mode': 'live_chk04_detector_adapter',
                'benchmark': attestation, 'source_csv_sha256': filehash(csv_path),
                'chk04_source_sha256': filehash(CHK04_FILE),
                'observations': generated, 'unexecuted_original_cases': 13,
                'review_workflow': 'separate mutable human_review.csv; PENDING by default',
                'limits': ['Adapter invokes production CHK04 detector but not full scanner CLI',
                           'The initial GET for BenchmarkTest00087 is setup only, not scored',
                           'Potential is abstention, never Confirmed',
                           'Manual curl artifacts are not used as predictions']}
    save_json(root / 'collection_manifest.json', manifest)
    return manifest


def verify(root: Path) -> dict:
    manifest = read_json(root / 'collection_manifest.json')
    if manifest.get('schema_version') != 1 or manifest.get('phase') != '7.2':
        raise EvaluationError('Wrong manifest schema')
    benchmark = manifest.get('benchmark', {})
    if (benchmark.get('commit') != PINNED_COMMIT or benchmark.get('csv_sha256') != PINNED_CSV_SHA256
            or benchmark.get('working_tree_clean') is not True):
        raise EvaluationError('Unverified benchmark provenance')
    source_file = root / 'source_expectedresults-1.2.csv'
    if not source_file.is_file() or filehash(source_file) != PINNED_CSV_SHA256 or manifest.get('source_csv_sha256') != PINNED_CSV_SHA256:
        raise EvaluationError('Source CSV missing or modified')
    source_labels_from_csv(source_file.read_text(encoding='utf-8'))
    if manifest.get('chk04_source_sha256') != filehash(CHK04_FILE):
        raise EvaluationError('CHK04 detector changed after collection')
    found = set()
    for entry in manifest.get('observations', []):
        case = entry.get('case_id')
        if case in found or case not in CASES or entry.get('check_id') != 'CHK04':
            raise EvaluationError('Unknown/duplicate case')
        found.add(case)
        if entry.get('method') != CASES[case]['method'] or entry.get('endpoint') != BASE + CASES[case]['path']:
            raise EvaluationError('Method/URL mismatch')
        p = entry.get('evidence_path')
        if p != f'{case}.http-evidence.json' or not HEX.fullmatch(str(entry.get('evidence_sha256', ''))):
            raise EvaluationError('Invalid evidence path/digest')
        artifact = root / p
        if not artifact.is_file() or filehash(artifact) != entry['evidence_sha256']:
            raise EvaluationError('HTTP evidence SHA-256 mismatch')
        evidence = read_json(artifact)
        if evidence.get('origin') != 'live_httpx_localhost_benchmark' or evidence.get('method') != entry['method'] or evidence.get('url') != entry['endpoint']:
            raise EvaluationError('Evidence origin, method or URL changed')
        computed = evaluate_evidence(evidence)
        # Ignore random test IDs: evaluate_evidence contains only stable metadata.
        if computed != entry['prediction']:
            raise EvaluationError('Detector prediction cannot be reproduced')
    if found != set(CASES):
        raise EvaluationError('Expected two distinct benchmark case observations')
    return manifest


def read_reviews(root: Path) -> dict:
    path = root / 'human_review.csv'
    with path.open(newline='', encoding='utf-8') as stream:
        rows = list(csv.DictReader(stream))
    if set(rows[0] if rows else ()) != {'case_id', 'review_status', 'reviewer', 'review_reference', 'notes'}:
        raise EvaluationError('Unexpected review CSV columns')
    if len(rows) != len(CASES) or {r['case_id'] for r in rows} != set(CASES):
        raise EvaluationError('Human review file must contain both cases once')
    for row in rows:
        if row['review_status'] not in ('PENDING', 'APPROVED', 'REJECTED'):
            raise EvaluationError('Invalid human review status')
        if row['review_status'] == 'APPROVED' and (not row['reviewer'].strip() or not row['review_reference'].strip()):
            raise EvaluationError('Approval requires named reviewer and traceable review reference')
    return {r['case_id']: r for r in rows}


def score(root: Path) -> dict:
    manifest = verify(root)
    reviews = read_reviews(root)
    counts = {k: 0 for k in ('TP', 'FP', 'TN', 'FN', 'ABSTAINED', 'PENDING_REVIEW', 'REJECTED_REVIEW', 'UNEXECUTED')}
    rows = []
    for entry in manifest['observations']:
        case = entry['case_id']
        review = reviews[case]
        status = entry['prediction']['status']
        if review['review_status'] == 'PENDING':
            outcome = 'PENDING_REVIEW'
        elif review['review_status'] == 'REJECTED':
            outcome = 'REJECTED_REVIEW'
        elif status in ('Potential', 'Inconclusive', 'Not Tested'):
            outcome = 'ABSTAINED'
        elif status == 'Confirmed':
            outcome = 'TP' if CASES[case]['expected'] else 'FP'
        elif status == 'No Issue Observed':
            outcome = 'FN' if CASES[case]['expected'] else 'TN'
        else:
            raise EvaluationError('Unsupported CHK04 prediction status')
        counts[outcome] += 1
        rows.append({'case_id': case, 'expected_vulnerability': CASES[case]['expected'],
                     'detector_status': status, 'outcome': outcome,
                     'review_status': review['review_status'], 'evidence_sha256': entry['evidence_sha256']})
    counts['UNEXECUTED'] = 13
    tp, fp, tn, fn = (counts[v] for v in ('TP', 'FP', 'TN', 'FN'))
    ratio = lambda n, d: round(n / d, 6) if d else None
    result = {'schema_version': 1, 'benchmark_version': 'OWASP Benchmark Java 1.2',
              'scope': '2 CHK04 cases in a 15-case Phase 7 subset; CHK11 and other cookie cases UNEXECUTED',
              'counts': counts, 'observations': rows,
              'metrics': {'precision': ratio(tp, tp + fp), 'recall': ratio(tp, tp + fn),
                          'false_positive_rate': ratio(fp, fp + tn),
                          'scored_fraction_of_15': ratio(tp + fp + tn + fn, 15)},
              'source_manifest_sha256': filehash(root / 'collection_manifest.json'),
              'limitations': ['Human review is a declared CSV workflow, not a cryptographic signature',
                              'Full CLI was not executed; production CHK04 function was used unchanged',
                              'Potential remains ABSTAINED, not Confirmed',
                              'Unexecuted cases are not included as FN or TN']}
    save_json(root / 'score.json', result)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('collect', 'verify', 'score'))
    parser.add_argument('--root', type=Path, required=True, help='New evidence directory for collect; existing for verify/score')
    parser.add_argument('--docker-prefix', default='sudo docker', help='Local Docker command, e.g. "sudo docker" or "docker"')
    parser.add_argument('--container', default='owa-benchmark')
    parser.add_argument('--base', default=BASE)
    parser.add_argument('--confirm-local-benchmark', action='store_true', help='Required for live network operations')
    args = parser.parse_args(argv)
    try:
        if args.action == 'collect':
            if not args.confirm_local_benchmark:
                raise EvaluationError('Live collection requires --confirm-local-benchmark')
            manifest = capture(args.root, shlex.split(args.docker_prefix), args.container, args.base)
            print('PASS: collected two real localhost HTTP responses through existing CHK04 detector; human review PENDING')
            for entry in manifest['observations']:
                print(entry['case_id'], entry['method'], entry['prediction']['status'], entry['evidence_sha256'])
        elif args.action == 'verify':
            verify(args.root)
            print('PASS: original source labels, pinned revision, file hashes and CHK04 detector replay verified')
        else:
            report = score(args.root)
            print(json.dumps({'counts': report['counts'], 'metrics': report['metrics']}, indent=2))
        return 0
    except (EvaluationError, OSError, httpx.HTTPError, subprocess.SubprocessError, UnicodeError, ValueError) as ex:
        print(f'FAIL: {ex}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
