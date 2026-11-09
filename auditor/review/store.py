"""Local-only AI review schema, evidence validation and atomic storage.

No AI calls, target requests, HTML rendering or automatic verification occurs.
Validated references establish provenance links, not the truth of model prose.
"""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from auditor.reporting.validation import load_report_data, unique_object, reject_constant
from auditor.reporting.guardrails import acceptable_prose
from auditor.resume_engine import lock_run

MAX_BYTES = 4 * 1024 * 1024
REVIEW_PATH = 'results/ai_review.json'
SUPPORTED = {'CHK05': 'review_error_context', 'CHK07': 'review_reflection_context',
             'CHK08': 'review_input_handling', 'CHK09':'review_access_policy',
             'CHK10':'review_access_policy', 'CHK11':'review_query_parameterization',
             'CHK12':'review_session_revocation'}


class ReviewError(ValueError):
    """Safe, fixed-message validation failure; no rejected content is echoed."""


@lru_cache(maxsize=1)
def schema():
    path = Path(__file__).parents[1] / 'reporting/schemas/ai_review.json'
    value = json.loads(path.read_text(encoding='utf-8'))
    Draft202012Validator.check_schema(value)
    return value


def _check(value, definition=None):
    spec = schema() if definition is None else schema()['$defs'][definition]
    if not Draft202012Validator(spec, format_checker=FormatChecker()).is_valid(value):
        raise ReviewError('AI review schema validation failed.')
    if definition == 'payload' and not acceptable_prose(value):
        raise ReviewError('AI review text failed output safety validation.')


def _read(path):
    try:
        with path.open('rb') as handle:
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ReviewError('AI review file exceeds the size limit.')
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise ReviewError('AI review file is unreadable or invalid.') from None


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                   ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _index(records):
    result = {}
    for record in records:
        identifier = record['id']
        if identifier in result:
            raise ReviewError('Duplicate source record ID.')
        result[identifier] = record
    return result


def _source(run):
    try:
        data = load_report_data(run)
        tests = _index(data['tests'])
        evidence = _index(data['evidence'])
        if {p.stem for p in (Path(run) / 'evidence').glob('*.json')} != set(evidence):
            raise ReviewError('Source evidence filename does not match its ID.')
        for item in evidence.values():
            info = item['content_hash']
            actual = _digest({k: v for k, v in item.items() if k != 'content_hash'})
            if (info['algorithm'] != 'sha256' or info['value'] != actual or
                    info['scope'] != 'Canonical JSON excluding content_hash'):
                raise ReviewError('Source evidence hash validation failed.')
        # Snapshot parsed source data, including all evidence. JSON formatting is irrelevant.
        source_hash = _digest({k: data[k] for k in ('scan', 'tests', 'findings', 'evidence')})
        eligible = {key: t for key, t in tests.items() if t['rule_id'] in SUPPORTED
                    and t['status'] != 'Not Tested' and t['evidence_refs']}
        for test in eligible.values():
            _validate_refs(test, test['evidence_refs'], evidence)
        return data['scan']['id'], source_hash, eligible, evidence
    except ReviewError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise ReviewError('Source result validation failed.') from None


def _validate_refs(test, refs, evidence):
    for ref in refs:
        if ref not in test['evidence_refs'] or ref not in evidence:
            raise ReviewError('Evidence reference does not belong to the reviewed test.')
        item = evidence[ref]
        owners = item.get('test_ids', [])
        if not isinstance(owners, list) or any(not isinstance(x, str) for x in owners):
            raise ReviewError('Source evidence ownership is invalid.')
        owners = owners + ([item['test_id']] if item.get('test_id') else [])
        if test['id'] not in owners:
            raise ReviewError('Source evidence backlink does not match the reviewed test.')


def _status(eligible, reviews):
    if not eligible:
        return 'not_applicable'
    if not reviews:
        return 'pending'
    return 'complete' if len(reviews) == len(eligible) else 'partial'


def _validate(state, source):
    _check(state)
    run_id, fingerprint, eligible, evidence = source
    if state['run_id'] != run_id or state['source_hash'] != fingerprint:
        raise ReviewError('AI review source is stale or belongs to another run.')
    seen = set()
    for item in state['reviews']:
        test = eligible.get(item['test_id'])
        if test is None:
            raise ReviewError('Reviewed test is missing, unsupported or not eligible.')
        if item['test_id'] in seen:
            raise ReviewError('Duplicate review for the same test.')
        seen.add(item['test_id'])
        if item['rule_id'] != test['rule_id'] or item['scanner_status'] != test['status']:
            raise ReviewError('Review metadata differs from scanner results.')
        if not acceptable_prose(item['payload']):
            raise ReviewError('AI review text failed output safety validation.')
        _validate_refs(test, item['payload']['evidence_refs'], evidence)
        if item['payload']['suggested_verification'] not in ('none', SUPPORTED[test['rule_id']]):
            raise ReviewError('Suggested verification does not match the reviewed rule.')
    if state['status'] != _status(eligible, state['reviews']):
        raise ReviewError('AI review completion status is inconsistent.')
    return state


def _destination(run):
    run = Path(run).resolve()
    if not run.is_dir() or not (run / 'results').is_dir():
        raise ReviewError('Run and results directories are required.')
    for relative in (REVIEW_PATH, 'results', '.resume.lock'):
        if (run / relative).is_symlink():
            raise ReviewError('Symlink review destinations are not supported.')
    return run, run / REVIEW_PATH


def _write(path, state):
    # Validate/serialize before atomic replacement, avoiding partial or oversized writes.
    raw = json.dumps(state, indent=2, ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(raw) > MAX_BYTES:
        raise ReviewError('AI review store exceeds the size limit.')
    from auditor.scanner import save_json
    save_json(path, state)


def initialize(run):
    """Create an empty pending store. Existing valid reviews are preserved."""
    run, path = _destination(run)
    with lock_run(run):
        source = _source(run)
        if path.exists():
            return deepcopy(_validate(_read(path), source))
        state = {'schema_version': 1, 'run_id': source[0], 'source_hash': source[1],
                 'status': _status(source[2], []), 'reviews': []}
        _validate(state, source)
        _write(path, state)
        return deepcopy(state)


def load_reviews(run):
    """Validate persisted review structure, source snapshot and evidence links."""
    run, path = _destination(run)
    with lock_run(run):
        return deepcopy(_validate(_read(path), _source(run)))


def save_review(run, test_id, payload, *, provider, model):
    """Future integration boundary: caller binds test/provider, model supplies payload only.

    Upserts one review under the run lock. Failed validation leaves files unchanged.
    Provider/model are supplied by the host; metadata is not proof of an actual AI call.
    """
    _check(payload, 'payload')
    run, path = _destination(run)
    with lock_run(run):
        source = _source(run)
        if path.exists():
            state = _validate(_read(path), source)
        else:
            state = {'schema_version': 1, 'run_id': source[0], 'source_hash': source[1],
                     'status': _status(source[2], []), 'reviews': []}
        test = source[2].get(test_id)
        if test is None:
            raise ReviewError('Reviewed test is missing, unsupported or not eligible.')
        entry = {'test_id': test_id, 'rule_id': test['rule_id'],
                 'scanner_status': test['status'], 'provider': provider, 'model': model,
                 'created_at': datetime.now(timezone.utc).isoformat(),
                 'review_required': True, 'payload': deepcopy(payload)}
        state['reviews'] = [r for r in state['reviews'] if r['test_id'] != test_id] + [entry]
        state['status'] = _status(source[2], state['reviews'])
        _validate(state, source)
        _write(path, state)
        return deepcopy(state)


def main():
    parser = argparse.ArgumentParser(description='Initialize or validate local AI-review storage; no network requests.')
    parser.add_argument('--run', required=True, type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--init', action='store_true', help='Create an empty store; preserve existing valid reviews')
    action.add_argument('--validate', action='store_true', help='Validate an existing review store')
    args = parser.parse_args()
    try:
        state = initialize(args.run) if args.init else load_reviews(args.run)
    except (ReviewError, OSError, ValueError):
        # Do not print raw provider content, source values or filesystem exception details.
        parser.exit(1, 'AI review validation: FAIL. Check source integrity, review schema and source version.\n')
    print('AI review validation: PASS')
    print('Review status:', state['status'])
    print('Stored reviews:', len(state['reviews']))
    print('Store:', str(args.run / REVIEW_PATH))
    print('No AI generation, target requests or follow-up tests were performed.')


if __name__ == '__main__':
    main()
