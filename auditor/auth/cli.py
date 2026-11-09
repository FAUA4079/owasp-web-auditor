"""Separate preflight CLI branch: no scan, AI input, reports or checkpoints."""
import argparse
import json
import asyncio
from pathlib import Path
from auditor.__main__ import default_profile_path, load_profile
from .project import load_project, resolve_credentials, prompt_credentials, ProjectError
from .sessions import check_accounts


def main():
    parser = argparse.ArgumentParser(prog='owasp-auditor', description='Account preflight for AuditShop JSON authentication.')
    parser.add_argument('--project', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--validate-project', action='store_true', help='Validate configuration offline; credentials are not read')
    mode.add_argument('--check-accounts', action='store_true', help='Login once per account, verify identity, then attempt logout')
    mode.add_argument('--assess', action='store_true', help='Run bounded AuditShop ownership, guest access, SQL differential and logout replay checks')
    parser.add_argument('--rbac-policy', type=Path, help='Opt-in approved read-only CHK13 policy JSON; requires --assess')
    parser.add_argument('--prompt-credentials', action='store_true', help='Prompt for account emails and hidden passwords instead of reading environment credentials')
    parser.add_argument('--output', type=Path, default=Path('runs'))
    from auditor.reporting.ai import add_ai_arguments, apply_ai_arguments
    add_ai_arguments(parser)
    parser.add_argument('--profile', type=Path, default=default_profile_path())
    args = parser.parse_args()
    apply_ai_arguments(args)
    try:
        project = load_project(args.project)
        if args.rbac_policy and not args.assess:
            raise ProjectError('--rbac-policy requires --assess.')
        policy = None
        if args.rbac_policy:
            from .rbac import load_policy
            policy = load_policy(args.rbac_policy, project)
        if args.validate_project:
            print('Project configuration: VALID')
            print('Authentication adapter: auditshop-json-v1')
            print('Accounts configured:', len(project['accounts']))
            print('No credentials read or requests sent.')
            return
        profile = load_profile(args.profile)
        # Resolve ALL credentials before making the first network request.
        credentials = prompt_credentials(project) if args.prompt_credentials else resolve_credentials(project)
        if args.assess:
            if 'assessment' not in project:
                raise ProjectError('Assessment resources are required.')
            from auditor.auth.assessment import run_assessment
            path = asyncio.run(run_assessment(project, profile, credentials, args.output, rbac_policy=policy))
            credentials.clear()
            print('Report:', path / 'reports/report.html')
            if json.loads((path / 'scan.json').read_text())['stop_reason'] == 'interrupted':
                parser.exit(130)
            return
        result = asyncio.run(check_accounts(project, profile, credentials))
        credentials.clear()
    except KeyboardInterrupt:
        parser.exit(130, 'Account preflight interrupted. Server logout may be incomplete.\n')
    except (ProjectError, ValueError, OSError, EOFError):
        parser.exit(1, 'Account preflight configuration error. Check project/profile JSON and credential environment variables.\n')
    for account in result['accounts']:
        print(account['alias'] + ': ' + account['status'] +
              (' (' + account['reason'] + ')' if account['reason'] else ''))
        print('  Cleanup: ' + account['cleanup'])
    print('Requests attempted:', result['requests_attempted'])
    print('Identity verification only; no vulnerability scan or AI review was performed.')
    print('Session secrets were not saved. Logout acknowledgement is not a revocation test.')
    if any(a['status'] != 'Verified' or a['cleanup'] != 'logout_acknowledged' for a in result['accounts']):
        parser.exit(1)


if __name__ == '__main__':
    main()
