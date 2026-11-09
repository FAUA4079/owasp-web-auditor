"""Offline, opt-in Phase 6 manifest and privacy export utilities."""
import argparse
from pathlib import Path
from auditor.reporting.phase6 import save_manifest, verify_manifest
from auditor.reporting.html_report import write_report


def main():
    parser=argparse.ArgumentParser(description='Offline source-manifest and privacy export; no provider or target requests')
    parser.add_argument('--run', required=True, type=Path)
    command=parser.add_mutually_exclusive_group(required=True)
    command.add_argument('--snapshot', action='store_true')
    command.add_argument('--verify', action='store_true')
    command.add_argument('--export-private', type=Path, metavar='OUTPUT_HTML')
    args=parser.parse_args()
    try:
        if args.snapshot:
            obj=save_manifest(args.run)
            print('PASS: source manifest created for',len(obj['files']),'deterministic files')
        elif args.verify:
            valid=verify_manifest(args.run)
            print('PASS: deterministic source manifest unchanged' if valid else 'FAIL: deterministic source differs from manifest')
            if not valid: return 1
        else:
            if args.export_private.resolve() == (args.run/'reports/report.html').resolve():
                raise ValueError('Refusing to replace original report')
            output=write_report(args.run,privacy=True,output=args.export_private)
            print('PASS: best-effort redacted HTML export:',output)
    except (ValueError,OSError) as exc:
        parser.exit(1, 'FAIL: '+str(exc)+'\n')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
