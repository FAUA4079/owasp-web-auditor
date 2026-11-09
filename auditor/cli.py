"""Shared entry point for python -m auditor and installed commands."""
import sys


def main():
    if any(arg == '--project' or arg.startswith('--project=') or arg.startswith('--rbac-policy=') or arg in {'--check-accounts', '--validate-project', '--assess', '--rbac-policy'} for arg in sys.argv[1:]):
        from auditor.auth.cli import main as project_cli
        return project_cli()
    if any(arg == '--resume' or arg.startswith('--resume=') for arg in sys.argv[1:]):
        from auditor.resume_engine import resume_cli
        return resume_cli()
    from auditor.__main__ import main as scan_cli
    return scan_cli()
