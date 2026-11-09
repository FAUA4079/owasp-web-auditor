"""Validate report inputs locally; schema validation is not a security audit."""
import argparse
import json
from functools import lru_cache
from pathlib import Path
from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).parent / 'schemas'

@lru_cache(maxsize=6)
def validator(kind):
    if kind not in {'scan', 'tests', 'findings', 'evidence', 'coverage', 'integrity'}:
        raise ValueError('Unknown report schema')
    schema = json.loads((SCHEMA_DIR / (kind + '.json')).read_text(encoding='utf-8'))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)

def reject_constant(value):
    raise ValueError('Non-finite JSON number is not permitted')

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key is not permitted')
        result[key] = value
    return result

def read_validated(path, kind, label=None):
    label = label or path.name
    try:
        value = json.loads(path.read_text(encoding='utf-8'),
                          parse_constant=reject_constant, object_pairs_hook=unique_object)
    except (OSError, ValueError) as exc:
        raise ValueError(f'{label}: unreadable or invalid JSON ({type(exc).__name__})') from None
    error = next(validator(kind).iter_errors(value), None)
    if error is not None:
        # Paths identify fields; never echo rejected values into output.
        field = '/'.join(str(x) for x in error.absolute_path) or '(root)'
        raise ValueError(f'{label}: {field}: schema {error.validator} check failed')
    return value

def load_report_data(run_dir):
    run_dir = Path(run_dir)
    data = {kind: read_validated(run_dir / relative, kind, relative)
            for kind, relative in [('scan', 'scan.json'), ('tests', 'results/tests.json'),
                                   ('findings', 'results/findings.json')]}
    for kind in ('coverage', 'integrity'):
        relative = f'results/{kind}.json'
        path = run_dir / relative
        data[kind] = read_validated(path, kind, relative) if path.exists() else None
    data['evidence'] = [read_validated(path, 'evidence', 'evidence/' + path.name)
                        for path in sorted((run_dir / 'evidence').glob('*.json'))]
    return data

def main():
    parser = argparse.ArgumentParser(description='Validate the saved JSON inputs used by the HTML report.')
    parser.add_argument('--run', required=True, type=Path)
    args = parser.parse_args()
    try:
        data = load_report_data(args.run)
    except ValueError as exc:
        parser.exit(1, f'Report JSON validation: FAIL\n{exc}\n')
    print('Report JSON validation: PASS')
    print('Checked scan, tests, findings, available evidence, coverage and integrity.')
    for kind in ('coverage', 'integrity'):
        if data[kind] is None:
            print(f'{kind}: unavailable (optional for older runs)')
    print('Checkpoint, discovery, plan and request ledger are outside these schemas.')

if __name__ == '__main__':
    main()
