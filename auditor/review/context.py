"""Build minimized local AI-review context; no model or target network calls."""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from auditor.resume_engine import lock_run
from auditor.review.store import ReviewError, _source, _destination, _read, _write

CONTEXT_PATH = 'results/ai_context.json'
SIGNATURES = ('python_traceback_with_absolute_path', 'php_error_with_absolute_path')
LABELS = ('html_text', 'html_attribute', 'script_text', 'style_text', 'html_comment',
          'attribute_name', 'tag_name', 'plain_text', 'unclassified')
LIMITATIONS = {
 'CHK05': ['Only selected Python/PHP signatures are inspected.',
           'Live errors cannot be distinguished from documentation using this metadata.',
           'No paths, excerpts, messages or response bodies are included.'],
 'CHK07': ['Reflection is not proof of XSS.',
           'HTML parsing is heuristic and uses a bounded UTF-8 prefix; browser parsing may differ.',
           'No JavaScript execution, encoding safety or stored reflection is verified.',
           'Old runs may lack reflection context; missing data is not inferred.'],
 'CHK08': ['One baseline and one malformed numeric value are compared.',
           'A server error does not establish SQL injection or a service outage.',
           'Only supported error-signature types are compared; no full body difference is available.']}

LIMITATIONS.update({
 'CHK09':['Ownership policy is operator supplied.', 'Only declared resources and verified actors are compared.', 'Private markers and raw responses are omitted.'],
 'CHK10':['Only declared private orders are checked.', 'Guest access is compared with a verified owner control.', 'No session cookies or raw responses are included.'],
 'CHK11':['Boolean differences do not independently prove SQL execution.', 'Only two probe pairs on the AuditShop catalogue are tested.', 'No payloads, product IDs or response bodies are included.'],
 'CHK12':['Only immediate replay after logout is tested.', 'Session invalidation may differ across nodes or time.', 'Cookies and raw identity responses are omitted.'],
})
AUTH_BOOLEAN_FIELDS = {
 'CHK09':('owner_control_stable','private_resource_match','anonymous_probe'),
 'CHK10':('owner_control_stable','private_resource_match','anonymous_probe'),
 'CHK11':('baseline_stable','repeatable_boolean_differential','literal_rejection_observed'),
 'CHK12':('replayed_identity_matches',),
}


def _status(value):
    return value if type(value) is int and 100 <= value <= 599 else None


def _boolean(value):
    return value if type(value) is bool else None


def _types(value):
    if not isinstance(value, list):
        return []
    return sorted({item['type'] for item in value if isinstance(item, dict)
                   and item.get('type') in SIGNATURES})


def _project(test):
    obs = test.get('observed') or {}
    rule = test['rule_id']
    if rule == 'CHK05':
        return {'http_status': _status(obs.get('http_status')),
                'signature_types': _types(obs.get('signatures')),
                'signature_data_available': isinstance(obs.get('signatures'), list),
                'text_inspection_limited': _boolean(obs.get('text_inspection_limited')),
                'signature_limit_reached': _boolean(obs.get('signature_limit_reached')),
                'runtime_origin': 'not_determined'}
    common = {'baseline_status': _status(obs.get('baseline_status')),
              'probe_status': _status(obs.get('probe_status')),
              'comparison_stopped': (obs['stop_reason'] is not None) if 'stop_reason' in obs else None}
    if rule in AUTH_BOOLEAN_FIELDS:
        result = dict(common)
        result.update({key:_boolean(obs.get(key)) for key in AUTH_BOOLEAN_FIELDS[rule]})
        if rule == 'CHK11':
            for key in ('baseline_count','negative_control_count','probe_pairs'):
                value=obs.get(key)
                result[key]=value if type(value) is int and 0 <= value <= 100 else None
        if rule == 'CHK12':
            result['logout_status']=_status(obs.get('logout_status'))
        return result
    if rule == 'CHK07':
        raw = obs.get('reflection_context')
        context = {'state': 'unavailable', 'contexts': [], 'occurrences_in_prefix': None,
                   'inspection_limited': None, 'occurrence_limit_reached': None}
        if isinstance(raw, dict):
            state = raw.get('state')
            labels = raw.get('contexts')
            count = raw.get('occurrences_in_prefix')
            if (state in ('classified','parser_failed','unsupported','not_observed_in_prefix')
                    and isinstance(labels, list) and all(v in LABELS for v in labels)
                    and type(count) is int and 0 <= count <= 20
                    and type(raw.get('inspection_limited')) is bool
                    and type(raw.get('occurrence_limit_reached')) is bool):
                context = {'state': state, 'contexts': sorted(set(labels)),
                           'occurrences_in_prefix': count,
                           'inspection_limited': raw['inspection_limited'],
                           'occurrence_limit_reached': raw['occurrence_limit_reached']}
        return dict(common, marker_in_baseline=_boolean(obs.get('marker_in_baseline')),
                    marker_in_probe=_boolean(obs.get('marker_in_probe')),
                    reflection_context=context, browser_execution='not_tested')
    baseline = _types(obs.get('baseline_error_indicators'))
    probe = _types(obs.get('probe_error_indicators'))
    available = all(isinstance(obs.get(k), list) for k in
                    ('baseline_error_indicators', 'probe_error_indicators'))
    return dict(common, baseline_error_types=baseline, probe_error_types=probe,
                new_error_types=sorted(set(probe) - set(baseline)) if available else [],
                indicator_data_available=available,
                disclosure_inspection_supported=_boolean(obs.get('disclosure_inspection_supported')),
                full_response_comparison='not_available')


def _schema():
    return json.loads((Path(__file__).parents[1] / 'reporting/schemas/ai_context.json').read_text())


def _build(run):
    run_id, fingerprint, eligible, evidence = _source(run)
    records = []
    for identifier, test in eligible.items():
        # Context must agree with the observations in the cited, hashed evidence.
        # These three checks currently emit exactly one evidence record per test.
        if len(test['evidence_refs']) != 1:
            raise ReviewError('Context requires one observation evidence record per test.')
        item = evidence[test['evidence_refs'][0]]
        if not isinstance(test.get('observed'), dict) or item.get('observation') != test['observed']:
            raise ReviewError('Test observations differ from cited evidence.')
        records.append({'test_id': identifier, 'rule_id': test['rule_id'],
                        'scanner_status': test['status'], 'evidence_refs': list(test['evidence_refs']),
                        'observations': _project(test), 'limitations': LIMITATIONS[test['rule_id']]})
    state = {'schema_version': 1, 'run_id': run_id, 'source_hash': fingerprint,
             'status': 'ready' if records else 'not_applicable', 'contexts': records}
    if not Draft202012Validator(_schema()).is_valid(state):
        raise ReviewError('AI context schema validation failed.')
    return state


def _paths(run):
    run, _ = _destination(run)
    path = run / CONTEXT_PATH
    if path.is_symlink():
        raise ReviewError('Symlink context destination is not supported.')
    return run, path


def build_context(run):
    """Rebuild deterministic context from current saved evidence under the scan lock."""
    run, path = _paths(run)
    with lock_run(run):
        state = _build(run)
        _write(path, state)
        return deepcopy(state)


def load_context(run):
    """Reject stale or altered context by comparing it with a fresh local projection."""
    run, path = _paths(run)
    with lock_run(run):
        state = _read(path)
        if not Draft202012Validator(_schema()).is_valid(state):
            raise ReviewError('AI context schema validation failed.')
        if state != _build(run):
            raise ReviewError('AI context differs from current saved evidence. Rebuild it.')
        return deepcopy(state)


def main():
    parser = argparse.ArgumentParser(description='Build or validate minimized AI-review context locally; no network requests.')
    parser.add_argument('--run', required=True, type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--build', action='store_true')
    group.add_argument('--validate', action='store_true')
    args = parser.parse_args()
    try:
        state = build_context(args.run) if args.build else load_context(args.run)
    except (ReviewError, ValueError, OSError, TypeError, KeyError):
        parser.exit(1, 'AI context validation: FAIL. Check source integrity and rebuild context from valid results.\n')
    print('AI context validation: PASS')
    print('Context status:', state['status'])
    print('Context records:', len(state['contexts']))
    print('Store:', args.run / CONTEXT_PATH)
    print('No AI generation, target requests or follow-up tests were performed.')


if __name__ == '__main__':
    main()
