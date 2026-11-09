"""Account jars in memory; one shared request ledger, deadline and response budget."""
import asyncio
import json
import re
import httpx
from auditor.core.http_client import BoundedHTTPClient, ScanStopped, origin
from .project import unique_object


class SessionError(ValueError):
    pass


def response_json(response):
    if response['status_code'] != 200:
        raise SessionError('unexpected_http_status')
    if response['headers'].get('content-type', '').split(';')[0].strip().lower() != 'application/json':
        raise SessionError('response_not_json')
    try:
        value = json.loads(response['body'], object_pairs_hook=unique_object)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError) as exc:
        raise SessionError('invalid_json_response') from exc


def csrf_token(obj):
    value = obj.get('csrf_token')
    if (not isinstance(value, str) or not 1 <= len(value) <= 512
            or any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise SessionError('invalid_csrf_token')
    return value


class AccountSessions:
    """Use within an async context; do not serialize this object or its responses.

    This adapter logs in once per supplied identity. It is not an auth-bypass check.
    No redirects, automatic retries, refresh loops or business writes are permitted.
    """
    def __init__(self, project, profile, transport_factory=None):
        self.project = project
        self.budget = BoundedHTTPClient(project['base_url'], profile)
        self.transport_factory = transport_factory
        self.clients = {}
        self.tokens = {}
        self.logged_in = set()
        self.verified = set()
        self.cleanup = {}
        self.lock = asyncio.Lock()

    async def __aenter__(self):
        await self.budget.__aenter__()
        return self

    async def __aexit__(self, *args):
        try:
            # Best-effort server logout consumes the SAME budget; never bypass limits.
            for alias in sorted(self.logged_in):
                self.cleanup[alias] = 'not_completed'
                try:
                    response = await self.request(alias, '/api/logout', method='POST', body={})
                    self.cleanup[alias] = 'logout_acknowledged' if response['status_code'] == 204 else 'not_completed'
                except (ScanStopped, SessionError):
                    pass
        finally:
            for client in self.clients.values():
                client.cookies.clear()
                await client.aclose()
            self.clients.clear()
            self.tokens.clear()
            self.logged_in.clear()
            self.verified.clear()
            await self.budget.__aexit__(*args)

    async def request(self, alias, path, *, method='GET', body=None):
        resource_path = bool(re.fullmatch(r'/api/orders/[1-9][0-9]{0,18}', path))
        rbac_path = bool(re.fullmatch(r'/api/rbac/[a-z][a-z0-9_-]{0,31}', path))
        if path not in {'/api/csrf', '/api/login', '/api/me', '/api/logout'} and not resource_path and not rbac_path:
            raise SessionError('unsupported_auth_endpoint')
        if resource_path and int(path.rsplit('/', 1)[1]) not in {
                r['order_id'] for r in self.project.get('assessment', {}).get('order_resources', [])}:
            raise SessionError('undeclared_resource')
        if rbac_path and path.rsplit('/',1)[1] not in getattr(self, 'rbac_resource_ids', frozenset()):
            raise SessionError('undeclared_rbac_resource')
        expected_method = 'POST' if path in {'/api/login', '/api/logout'} else 'GET'
        if method != expected_method:
            raise SessionError('unsupported_auth_method')
        url = self.project['base_url'] + path
        if origin(url) != origin(self.budget.target):
            raise SessionError('off_scope_auth_url')
        headers = {}
        if method == 'POST':
            headers['X-CSRF-Token'] = self.tokens.get(alias, '')
        async with self.lock:
            result = await self.budget._request_once(
                url, session_client=self.clients[alias], method=method,
                json_body=body, headers=headers)
        if 300 <= result['status_code'] < 400:
            raise SessionError('auth_redirect_not_followed')
        return result

    async def login(self, account, credentials):
        alias = account['alias']
        if alias in self.clients:
            raise SessionError('account_already_attempted')
        profile = self.budget.profile
        self.clients[alias] = httpx.AsyncClient(
            verify=True, follow_redirects=False, trust_env=False,
            timeout=profile['request_timeout_seconds'],
            headers={'Accept-Encoding': 'identity', 'User-Agent': 'OWASP-Web-Auditor/0.1.0'},
            transport=self.transport_factory(alias) if self.transport_factory else None)
        obj = response_json(await self.request(alias, '/api/csrf'))
        self.tokens[alias] = csrf_token(obj)
        username, password = credentials
        obj = response_json(await self.request(alias, '/api/login', method='POST',
                                               body={'email': username, 'password': password}))
        # Track successful login even if subsequent identity validation fails.
        self.logged_in.add(alias)
        self.tokens[alias] = csrf_token(obj)
        identity = response_json(await self.request(alias, '/api/me'))
        if (type(identity.get('id')) is not int or identity['id'] != account['expected_id']
                or identity.get('role') != account['expected_role']):
            raise SessionError('identity_mismatch')
        self.verified.add(alias)


async def check_accounts(project, profile, credentials, transport_factory=None):
    results = []
    sessions = AccountSessions(project, profile, transport_factory)
    async with sessions:
        for account in project['accounts']:
            alias = account['alias']
            result = {'alias': alias, 'status': 'Not Verified', 'reason': None}
            try:
                await sessions.login(account, credentials[alias])
                result['status'] = 'Verified'
            except SessionError as exc:
                result['reason'] = str(exc)  # Closed adapter-generated reason codes only.
            except ScanStopped as exc:
                result['reason'] = str(exc)
            results.append(result)
    for result in results:
        result['cleanup'] = sessions.cleanup.get(result['alias'], 'no_authenticated_session')
    return {'schema_version': 1, 'operation': 'account_preflight',
            'accounts': results, 'requests_attempted': sessions.budget.request_count,
            'ledger': sessions.budget.ledger,
            'limitations': ['Identity verification only; no vulnerability assessment.',
                            'Logout acknowledgement does not prove session revocation.',
                            'Failed or interrupted cleanup may leave server sessions until expiry.',
                            'Sessions are not persisted or resumable.']}
