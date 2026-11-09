"""Strict, secret-free project configuration. Version 1 supports AuditShop JSON auth."""
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit
from auditor.__main__ import validate_url


class ProjectError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProjectError('Duplicate JSON key.')
        result[key] = value
    return result


def fields(value, required):
    if not isinstance(value, dict) or set(value) != set(required):
        raise ProjectError('Missing or unsupported configuration fields.')


def load_project(path):
    try:
        with Path(path).open('rb') as handle:
            raw = handle.read(32769)
        if len(raw) > 32768:
            raise ProjectError('Project configuration exceeds size limit.')
        project = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProjectError('Cannot read valid project JSON.') from exc
    if isinstance(project, dict) and 'assessment' in project:
        assessment = project.pop('assessment')
    else:
        assessment = None
    fields(project, ('schema_version', 'base_url', 'auth_adapter', 'accounts'))
    if type(project['schema_version']) is not int or project['schema_version'] != 1:
        raise ProjectError('Unsupported project schema version.')
    if project['auth_adapter'] != 'auditshop-json-v1':
        raise ProjectError('Unsupported authentication adapter.')
    url = project['base_url']
    if not isinstance(url, str) or len(url) > 2048:
        raise ProjectError('Invalid base URL.')
    try:
        normalized, host, _ = validate_url(url)
        parts = urlsplit(url)
        if parts.fragment or parts.path not in ('', '/') or parts.query:
            raise ValueError()
        # Credentials are sent only over verified HTTPS or a literal local address.
        if parts.scheme == 'http' and host not in {'127.0.0.1', '::1'}:
            raise ValueError()
    except ValueError as exc:
        raise ProjectError('Base URL must be an HTTPS origin or literal loopback HTTP origin.') from exc
    project['base_url'] = normalized.rstrip('/')
    accounts = project['accounts']
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= 4:
        raise ProjectError('Configure between one and four accounts.')
    aliases, ids = set(), set()
    for account in accounts:
        fields(account, ('alias', 'username_env', 'password_env', 'expected_id', 'expected_role'))
        alias = account['alias']
        if not isinstance(alias, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}', alias):
            raise ProjectError('Invalid account alias.')
        uid = account['expected_id']
        if type(uid) is not int or uid <= 0 or uid > 9223372036854775807:
            raise ProjectError('Expected identity must be a positive integer.')
        if alias in aliases or uid in ids:
            raise ProjectError('Account aliases and expected identities must be distinct.')
        aliases.add(alias); ids.add(uid)
        if account['expected_role'] not in ('customer', 'admin'):
            raise ProjectError('Invalid expected account role.')
        for key in ('username_env', 'password_env'):
            value = account[key]
            if not isinstance(value, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,99}', value):
                raise ProjectError('Credentials must reference environment variable names.')
    if assessment is not None:
        fields(assessment, ('order_resources',))
        resources = assessment['order_resources']
        if not isinstance(resources, list) or not 1 <= len(resources) <= 4:
            raise ProjectError('Configure one to four known order resources.')
        seen = set()
        for resource in resources:
            fields(resource, ('order_id', 'owner', 'other'))
            oid = resource['order_id']
            if type(oid) is not int or not 1 <= oid <= 9223372036854775807 or oid in seen:
                raise ProjectError('Order IDs must be distinct positive integers.')
            seen.add(oid)
            if (not isinstance(resource['owner'], str) or not isinstance(resource['other'], str)
                    or resource['owner'] not in aliases or resource['other'] not in aliases
                    or resource['owner'] == resource['other']):
                raise ProjectError('Resource actors must name two distinct configured accounts.')
            actors = {a['alias']: a for a in accounts}
            if any(actors[resource[k]]['expected_role'] != 'customer' for k in ('owner','other')):
                raise ProjectError('Ownership checks require customer actors.')
        project['assessment'] = assessment
    return project


def resolve_credentials(project, environ=None):
    environ = os.environ if environ is None else environ
    credentials = {}
    for account in project['accounts']:
        username = environ.get(account['username_env'])
        password = environ.get(account['password_env'])
        if (not isinstance(username, str) or not 1 <= len(username) <= 120
                or not isinstance(password, str) or not 1 <= len(password) <= 256
                or any(ord(c) < 32 for c in username + password)):
            raise ProjectError('Required credential environment variables are missing or invalid.')
        credentials[account['alias']] = (username, password)
    return credentials


def prompt_credentials(project):
    """Interactive secrets stay in this process, not command-line arguments."""
    import getpass
    import sys
    if not sys.stdin.isatty():
        raise ProjectError("Credential prompts require an interactive terminal.")
    values = {}
    for account in project['accounts']:
        alias = account['alias']
        values[account['username_env']] = input(alias + ' email: ').strip()
        values[account['password_env']] = getpass.getpass(alias + ' password: ')
    return resolve_credentials(project, values)
