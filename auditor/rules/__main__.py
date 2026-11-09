"""Offline inspectable registry; no network and no scanner execution."""
import argparse
import json
from auditor.rules import get_rule, list_rules, validate_registry


def main():
    parser = argparse.ArgumentParser(description='Offline research-backed CHK metadata registry')
    parser.add_argument('--check', choices=[f'CHK{i:02d}' for i in range(1, 14)])
    parser.add_argument('--json', action='store_true', help='Output registry metadata as JSON')
    parser.add_argument('--validate', action='store_true', help='Validate bundled metadata against JSON schema')
    args = parser.parse_args()
    validate_registry()
    if args.validate:
        print('PASS: 13 locally bundled CHK records are schema-valid (not detection accuracy validation).')
        return
    selected = (get_rule(args.check),) if args.check else list_rules()
    if args.json:
        # MappingProxyType and tuples require conversion to plain JSON types.
        def plain(obj):
            if hasattr(obj, 'items'):
                return {key: plain(value) for key, value in obj.items()}
            if isinstance(obj, tuple):
                return [plain(value) for value in obj]
            return obj
        print(json.dumps([plain(r) for r in selected], indent=2))
    else:
        for record in selected:
            sources = record['research']
            print(f"{record['id']}  {record['title']}  "
                  f"ASVS={','.join(sources['asvs']['requirement_ids']) or '-'} "
                  f"CWE={','.join(sources['cwe']['weakness_ids']) or '-'} "
                  f"[{sources['relationship']}]")


if __name__ == '__main__':
    main()
