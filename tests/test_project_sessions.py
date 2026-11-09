import asyncio
import copy
import json
from pathlib import Path
import tempfile
import unittest
import httpx
from auditor.auth.project import load_project, resolve_credentials, ProjectError
from auditor.auth.sessions import AccountSessions, check_accounts, SessionError

PROFILE = dict(profile_name='test', max_requests=20, request_timeout_seconds=2,
               scan_deadline_seconds=5, max_response_bytes=4096,
               max_depth=1, max_redirects=2, verify_tls=True)
PROJECT = {'schema_version': 1, 'base_url': 'http://127.0.0.1:8088',
           'auth_adapter': 'auditshop-json-v1', 'accounts': [
               {'alias': alias, 'username_env': alias.upper()+'_EMAIL',
                'password_env': alias.upper()+'_PASSWORD', 'expected_id': uid,
                'expected_role': 'customer'} for alias, uid in [('a',101),('b',102)]]}
CREDENTIALS = {'a': ('a@example.test','SECRET_PASSWORD_A'), 'b': ('b@example.test','SECRET_PASSWORD_B')}

class Body(httpx.AsyncByteStream):
    def __init__(self, value): self.value = value
    async def __aiter__(self): yield self.value


def response(obj, status=200, headers=None):
    return httpx.Response(status, headers={'content-type':'application/json', **(headers or {})},
                          stream=Body(json.dumps(obj).encode()))


class FakeShop:
    def __init__(self, fail=None): self.requests=[]; self.fail=fail
    def factory(self, alias):
        def handle(request):
            self.requests.append((alias, request))
            path=request.url.path
            cookie=request.headers.get('cookie','')
            if path == '/api/csrf':
                assert not cookie, 'Cookie crossed account boundary'
                return response({'csrf_token':'CSRF_ANON_'+alias}, headers={'set-cookie':'session=ANON_'+alias+'; Path=/'})
            if path == '/api/login':
                assert cookie=='session=ANON_'+alias
                assert request.headers['x-csrf-token']=='CSRF_ANON_'+alias
                assert json.loads(request.content)['password']==CREDENTIALS[alias][1]
                if self.fail=='redirect': return response({},302,{'location':'https://outside.example/'})
                if self.fail=='denied': return response({'error':'SECRET_RESPONSE'},401)
                return response({'csrf_token':'CSRF_AUTH_'+alias}, headers={'set-cookie':'session=AUTH_'+alias+'; Path=/'})
            assert cookie=='session=AUTH_'+alias
            if path == '/api/me':
                return response({'id':999 if self.fail=='identity' else (101 if alias=='a' else 102), 'role':'customer', 'email':'SECRET_EMAIL'})
            if path == '/api/logout':
                assert request.headers['x-csrf-token']=='CSRF_AUTH_'+alias
                return response({},204)
            raise AssertionError(path)
        return httpx.MockTransport(handle)


class ProjectTests(unittest.TestCase):
    def load(self, obj):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'p.json'; p.write_text(json.dumps(obj)); return load_project(p)
    def test_valid_configuration_and_environment_only_credentials(self):
        project=self.load(PROJECT);env={}
        for account in project['accounts']:
            user,pw=CREDENTIALS[account['alias']]
            env[account['username_env']]=user;env[account['password_env']]=pw
        self.assertEqual(resolve_credentials(project,env),CREDENTIALS)
        with self.assertRaises(ProjectError): resolve_credentials(project,{})
    def test_unknown_fields_and_duplicate_id_rejected(self):
        obj=copy.deepcopy(PROJECT);obj['password']='SECRET'
        with self.assertRaises(ProjectError): self.load(obj)
        obj=copy.deepcopy(PROJECT);obj['accounts'][1]['expected_id']=101
        with self.assertRaises(ProjectError): self.load(obj)
    def test_unsafe_base_urls_rejected(self):
        for url in ['http://example.test','https://a:b@example.test','https://example.test/path',
                    'https://example.test/?key=SECRET','https://example.test/#x','http://localhost:8088']:
            with self.subTest(url=url):
                obj=copy.deepcopy(PROJECT);obj['base_url']=url
                with self.assertRaises(ProjectError): self.load(obj)
    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'p.json';p.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(ProjectError): load_project(p)


class SessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_isolated_cookie_rotation_identity_logout_and_redaction(self):
        shop=FakeShop();result=await check_accounts(PROJECT,PROFILE,CREDENTIALS,shop.factory)
        self.assertEqual([a['status'] for a in result['accounts']],['Verified','Verified'])
        self.assertEqual([a['cleanup'] for a in result['accounts']],['logout_acknowledged']*2)
        self.assertEqual(result['requests_attempted'],8)
        self.assertEqual([r['method'] for r in result['ledger']],['GET','POST','GET']*2+['POST']*2)
        for secret in ['SECRET','CSRF_','AUTH_','ANON_','example.test']:
            self.assertNotIn(secret,json.dumps(result))
    async def test_wrong_identity_does_not_verify(self):
        result=await check_accounts(PROJECT,PROFILE,CREDENTIALS,FakeShop('identity').factory)
        self.assertTrue(all(a['reason']=='identity_mismatch' for a in result['accounts']))
    async def test_login_failure_no_retry_or_secret_echo(self):
        result=await check_accounts(PROJECT,PROFILE,CREDENTIALS,FakeShop('denied').factory)
        self.assertEqual(result['requests_attempted'],4)
        self.assertTrue(all(a['status']=='Not Verified' for a in result['accounts']))
        self.assertNotIn('SECRET',json.dumps(result))
    async def test_redirect_never_followed(self):
        shop=FakeShop('redirect');result=await check_accounts(PROJECT,PROFILE,CREDENTIALS,shop.factory)
        self.assertTrue(all(a['reason']=='auth_redirect_not_followed' for a in result['accounts']))
        self.assertTrue(all(r.url.host=='127.0.0.1' for _,r in shop.requests))
    async def test_budget_shared_and_cleanup_does_not_bypass(self):
        result=await check_accounts(PROJECT,dict(PROFILE,max_requests=3),CREDENTIALS,FakeShop().factory)
        self.assertEqual(result['requests_attempted'],3)
        self.assertEqual(result['accounts'][0]['status'],'Verified')
        self.assertEqual(result['accounts'][0]['cleanup'],'not_completed')
        self.assertEqual(result['accounts'][1]['reason'],'request_budget_exhausted')
    async def test_deadline_is_shared(self):
        async def handle(request):
            await asyncio.sleep(.1)
            return response({})
        result=await check_accounts(PROJECT,dict(PROFILE,scan_deadline_seconds=.01),CREDENTIALS,
                                    lambda alias:httpx.MockTransport(handle))
        # A 10 ms deadline may expire before the first request on a slow host.
        # Assert the safety invariant, not a scheduler-dependent exact count.
        self.assertLessEqual(result['requests_attempted'], 1)
        self.assertEqual(len(result['ledger']), result['requests_attempted'])
        self.assertTrue(all(a['reason']=='scan_deadline_reached' for a in result['accounts']))
    async def test_size_limit_and_encoding_are_enforced(self):
        for headers,body,reason in [({},b'x'*4096,'response_size_cap_reached'),
                                    ({'content-encoding':'gzip'},b'x','encoded_response_not_supported')]:
            result=await check_accounts(PROJECT,PROFILE,CREDENTIALS,
                lambda alias:httpx.MockTransport(lambda request:httpx.Response(200,headers=headers,stream=Body(body))))
            self.assertTrue(all(a['reason']==reason for a in result['accounts']))
    async def test_sessions_closed_and_unsupported_endpoints_blocked(self):
        sessions=AccountSessions(PROJECT,PROFILE,FakeShop().factory)
        async with sessions:
            await sessions.login(PROJECT['accounts'][0],CREDENTIALS['a'])
            with self.assertRaises(SessionError): await sessions.request('a','/api/orders/1002')
            with self.assertRaises(SessionError): await sessions.login(PROJECT['accounts'][0],CREDENTIALS['a'])
        self.assertEqual(sessions.clients,{})
        self.assertEqual(sessions.tokens,{})
        self.assertEqual(sessions.budget.request_count,4)
