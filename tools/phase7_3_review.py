#!/usr/bin/env python3
"""Phase 7.3: review packet, explicit human attestations, and audited scoring.

No automatic approval; does not change CHK04 or source-derived labels.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

spec = importlib.util.spec_from_file_location('phase7_2_chk04', Path(__file__).with_name('phase7_2_chk04.py'))
p72 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p72)

class ReviewError(ValueError):
    pass


def h(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(root):
    manifest = p72.verify(root)
    review = p72.read_reviews(root)
    return manifest, review


def checkpoint(root, case):
    manifest, review = load(root)
    entry = next(x for x in manifest['observations'] if x['case_id'] == case)
    ev = p72.read_json(root / entry['evidence_path'])
    cookies = [v for k, v in ev['response_headers'] if k.lower() == 'set-cookie']
    # Do not print raw cookie values or include them in review packet.
    cookie_summary = [{'cookie_name': c.split('=', 1)[0].strip(), 'secure': bool(re.search(r'(?:^|;)\s*Secure\s*(?:;|$)', c, re.I))} for c in cookies]
    return {'case_id': case, 'expected_vulnerability': p72.CASES[case]['expected'],
            'method': entry['method'], 'url': entry['endpoint'],
            'detector_status': entry['prediction']['status'], 'cookies': cookie_summary,
            'evidence_sha256': entry['evidence_sha256'],
            'manifest_sha256': h(root / 'collection_manifest.json'),
            'source_sha256': h(root / 'source_expectedresults-1.2.csv'),
            'detector_sha256': h(p72.CHK04_FILE)}


def packet(root, dest):
    load(root)
    rows = [checkpoint(root, case) for case in p72.CASES]
    lines = ['# Phase 7.3 — Independent human review packet', '',
             'Do not approve based on this summary alone. Independently inspect the pinned Java source, original expected-results CSV, raw request method/endpoint and captured HTTP header evidence.',
             'A review decision is a human attestation, **not** a cryptographic signature. This packet redacts cookie values.', '']
    for item in rows:
        lines.extend([f"## {item['case_id']}", '',
                      f"- Benchmark source label: {'vulnerable' if item['expected_vulnerability'] else 'non-vulnerable'}",
                      f"- Request: `{item['method']} {item['url']}`",
                      f"- Unchanged production CHK04 output: `{item['detector_status']}`",
                      f"- Cookies (names and Secure flags only): `{json.dumps(item['cookies'])}`",
                      f"- Evidence SHA-256: `{item['evidence_sha256']}`",
                      f"- Manifest SHA-256: `{item['manifest_sha256']}`",
                      f"- Source CSV SHA-256: `{item['source_sha256']}`", '',
                      '- [ ] Verified exact source label against pinned CSV',
                      '- [ ] Verified servlet HTTP method, URL and cookie emission in pinned source',
                      '- [ ] Independently inspected preserved evidence and its SHA-256',
                      '- [ ] Verified CHK04 output uses unchanged production detector',
                      '- [ ] Documented any method/label/applicability limitations', ''])
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return dest


def atomic_csv(path, rows):
    with NamedTemporaryFile('w', encoding='utf-8', newline='', dir=path.parent, delete=False) as f:
        temp = Path(f.name)
        writer = csv.DictWriter(f, fieldnames=['case_id', 'review_status', 'reviewer', 'review_reference', 'notes'])
        writer.writeheader()
        writer.writerows(rows)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def attest(root, case, decision, reviewer, reference, notes, evidence_sha256, confirmation):
    if not confirmation:
        raise ReviewError('Explicit --confirm-independent-review required')
    for value, label in [(reviewer, 'reviewer'), (reference, 'review reference'), (notes, 'review notes')]:
        if not value or not value.strip() or len(value) > 500:
            raise ReviewError(f'Non-empty {label} required (max 500 chars)')
    if not re.fullmatch(r'[a-zA-Z0-9_.:/-]{3,120}', reference):
        raise ReviewError('Review reference must be a traceable identifier')
    if case not in p72.CASES or decision not in ('APPROVED', 'REJECTED'):
        raise ReviewError('Invalid case or decision')
    if not re.fullmatch('[0-9a-f]{64}', evidence_sha256 or ''):
        raise ReviewError('Provide exact 64-character evidence digest')
    cp = checkpoint(root, case)
    if evidence_sha256 != cp['evidence_sha256']:
        raise ReviewError('Reviewer-provided evidence digest does not match')
    _, previous = load(root)
    if previous[case]['review_status'] != 'PENDING':
        raise ReviewError('Non-pending review cannot be overwritten; preserve audit history')
    rows = []
    for c in p72.CASES:
        row = dict(previous[c])
        if c == case:
            row.update(review_status=decision, reviewer=reviewer.strip(), review_reference=reference.strip(), notes=notes.strip())
        rows.append(row)
    record_path = root / f'{case}.review-attestation.json'
    if record_path.exists():
        raise ReviewError('Review attestation already exists')
    record = {'schema_version': 1, 'reviewed_at_utc': datetime.now(timezone.utc).isoformat(),
              'reviewer': reviewer.strip(), 'review_reference': reference.strip(), 'notes': notes.strip(),
              'decision': decision, 'checkpoint': cp,
              'limitations': 'Human assertion recorded; not cryptographically signed'}
    p72.save_json(record_path, record, sensitive=True)
    atomic_csv(root / 'human_review.csv', rows)
    return record


def audit(root):
    manifest, reviews = load(root)
    results = []
    for case in p72.CASES:
        decision = reviews[case]['review_status']
        record_path = root / f'{case}.review-attestation.json'
        if decision == 'PENDING':
            if record_path.exists():
                raise ReviewError('Orphaned review attestation for pending case')
            results.append((case, 'PENDING'))
            continue
        if not record_path.is_file():
            raise ReviewError(f'Missing Phase 7.3 attestation for {case}')
        record = p72.read_json(record_path)
        row = reviews[case]
        if (record.get('schema_version') != 1 or record.get('decision') != decision or
                any(record.get(k) != row.get(v) for k, v in [('reviewer', 'reviewer'), ('review_reference', 'review_reference'), ('notes', 'notes')]) or
                record.get('checkpoint') != checkpoint(root, case)):
            raise ReviewError(f'Review attestation/evidence/CSV mismatch for {case}')
        results.append((case, decision))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for name in ('packet', 'attest', 'audit', 'score'):
        sp = sub.add_parser(name)
        sp.add_argument('--root', type=Path, required=True)
        if name == 'packet':
            sp.add_argument('--output', type=Path)
        if name == 'attest':
            sp.add_argument('--case', required=True, choices=list(p72.CASES))
            sp.add_argument('--decision', required=True, choices=['APPROVED', 'REJECTED'])
            sp.add_argument('--reviewer', required=True)
            sp.add_argument('--reference', required=True)
            sp.add_argument('--notes', required=True)
            sp.add_argument('--evidence-sha256', required=True)
            sp.add_argument('--confirm-independent-review', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'packet':
            path = packet(args.root, args.output or args.root / 'human_review_packet.md')
            print(f'PASS: redacted human-review packet written: {path} (no decisions approved)')
        elif args.action == 'attest':
            attest(args.root, args.case, args.decision, args.reviewer, args.reference, args.notes,
                   args.evidence_sha256, args.confirm_independent_review)
            print(f'RECORDED: human {args.decision} attestation for {args.case}; not a cryptographic signature')
        elif args.action == 'audit':
            for case, status in audit(args.root):
                print(f'{case}: {status}')
            print('PASS: all review attestations match current evidence and source')
        else:
            audit(args.root)
            result = p72.score(args.root)
            print(json.dumps({'counts': result['counts'], 'metrics': result['metrics']}, indent=2))
        return 0
    except (ReviewError, p72.EvaluationError, OSError, ValueError) as ex:
        print(f'FAIL: {ex}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
