"""First-party CHK13 controlled-fixture tests; no real internet or AI classifications."""
import contextlib
import copy
import io
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import unittest

import httpx
from auditor.auth.rbac import load_policy, role_access_check
from auditor.auth.project import ProjectError
from auditor.auth.sessions import AccountSessions, SessionError
from auditor.auth.assessment import run_assessment
from auditor.reporting.validation import load_report_data
from auditor.verification.integrity import audit_run
from test_authenticated_assessment import Shop, config, CREDENTIALS, REAL_CLIENT
from test_project_sessions import PROFILE, response


def project():
    p=config()
    p['accounts'].append({'alias':'admin','username_env':'ADMIN_EMAIL','password_env':'ADMIN_PASSWORD',
                          'expected_id':103,'expected_role':'admin'})
    return p


def policy():
    return {'schema_version':1,'base_url':project()['base_url'],
            'authorization':{'approved_by':'Test lab owner','approval_reference':'LOCAL-LAB-001','authorized_for_testing':True},
            'cases':[{'resource_id':'staff-report','allow':'admin','deny':'a'}]}


class PolicyValidationTests(unittest.TestCase):
    def check(self, data):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/'policy.json';file.write_text(json.dumps(data))
            return load_policy(file,project())

    def test_approved_exact_matrix(self):
        self.assertEqual(self.check(policy())['cases'][0]['allow'],'admin')

    def test_rejects_unsafe_policy(self):
        mutations=[lambda p:p['authorization'].update(authorized_for_testing=False),
                   lambda p:p.update(base_url='https://other.test'),
                   lambda p:p['cases'][0].update(resource_id='../admin'),
                   lambda p:p['cases'][0].update(resource_id='x?token=1'),
                   lambda p:p['cases'][0].update(deny='admin'),
                   lambda p:p['cases'][0].update(deny='missing'),
                   lambda p:p['cases'][0].update(deny=['a']),
                   lambda p:p.update(schema_version=True),
                   lambda p:p['cases'][0].update(resource_id='a'*50),
                   lambda p:p.update(cases=[]),
                   lambda p:p['cases'][0].update(extra='unexpected'),
                   lambda p:p['authorization'].update(approved_by='x')]
        for mutation in mutations:
            p=policy();mutation(p)
            with self.subTest(p=p), self.assertRaises(ProjectError):self.check(p)

    def test_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/'policy.json';file.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(ProjectError):load_policy(file,project())


class RbacShop(Shop):
    def handle(self,r):
        if r.url.path=='/api/rbac/staff-report':
            self.requests.append(r)
            cookie=r.headers.get('cookie','')
            actor='admin' if 'AUTH_admin' in cookie else ('a' if 'AUTH_a' in cookie else None)
            if actor=='admin' or (actor=='a' and self.scenario=='rbac_bypass'):
                return response({'resource':{'id':'staff-report','private_marker':'DO_NOT_EXPOSE_RBAC_SECRET'}})
            if actor=='a' and self.scenario=='misleading200':
                return response({'resource':{'id':'other','private_marker':'PUBLIC'}})
            return response({},403)
        if r.url.path in {'/api/login','/api/me'}:
            # Add admin account support without changing the existing AuditShop fixture.
            if r.url.path=='/api/login' and json.loads(r.content)['email'].startswith('admin@'):
                self.requests.append(r)
                return response({'csrf_token':'TOKEN'},headers={'set-cookie':'session=AUTH_admin; Path=/'})
            if r.url.path=='/api/me' and 'AUTH_admin' in r.headers.get('cookie',''):
                self.requests.append(r)
                return response({'id':103,'role':'admin'})
        return super().handle(r)


class RBACEvaluationTests(unittest.IsolatedAsyncioTestCase):
    async def evaluate(self,scenario):
        shop=RbacShop(scenario)
        credentials={**CREDENTIALS,'admin':('admin@example.test','TEST_ADMIN_PASSWORD')}
        def factory(**kwargs):
            if kwargs.get('transport') is None:kwargs['transport']=shop.transport('guest')
            return REAL_CLIENT(**kwargs)
        with tempfile.TemporaryDirectory() as d:
            with patch('httpx.AsyncClient',side_effect=factory),contextlib.redirect_stdout(io.StringIO()):
                run=await run_assessment(project(),dict(PROFILE,max_requests=75,scan_deadline_seconds=30),credentials,
                        Path(d),transport_factory=shop.transport,generate_ai=False,rbac_policy=policy())
            report=load_report_data(run)
            self.assertEqual(audit_run(run),[])
            secret_files=''.join(x.read_text() for x in run.rglob('*') if x.is_file())
            for secret in ('DO_NOT_EXPOSE_RBAC_SECRET','TEST_ADMIN_PASSWORD','AUTH_admin'):
                self.assertNotIn(secret,secret_files)
            cases=[x for x in report['tests'] if x['rule_id']=='CHK13']
            self.assertEqual(len(cases),1)
            self.assertTrue(any(t['rule_id']=='CHK12' for t in report['tests']))
            self.assertTrue(all(r.url.host=='127.0.0.1' for r in shop.requests))
            return cases[0],report,shop

    async def test_secure_role_policy(self):
        test,_,_=await self.evaluate('fixed')
        self.assertEqual(test['status'],'No Issue Observed')
        self.assertEqual(test['request_count'],3)

    async def test_role_bypass_is_evidence_confirmed(self):
        test,report,_=await self.evaluate('rbac_bypass')
        self.assertEqual(test['status'],'Confirmed')
        self.assertTrue(test['observed']['denied_actor_received_same_private_resource'])
        self.assertTrue(any(f['rule_id']=='CHK13' for f in report['findings']))

    async def test_misleading_200_not_a_confirmed_bypass(self):
        test,_,_=await self.evaluate('misleading200')
        self.assertEqual(test['status'],'Inconclusive')

    async def test_absent_policy_keeps_existing_behavior(self):
        shop=Shop('fixed')
        def factory(**kwargs):
            if kwargs.get('transport') is None:kwargs['transport']=shop.transport('guest')
            return REAL_CLIENT(**kwargs)
        with tempfile.TemporaryDirectory() as d:
            with patch('httpx.AsyncClient',side_effect=factory),contextlib.redirect_stdout(io.StringIO()):
                run=await run_assessment(config(),dict(PROFILE,max_requests=60),CREDENTIALS,Path(d),transport_factory=shop.transport,generate_ai=False)
            report=load_report_data(run)
            self.assertEqual(len(report['tests']),5)
            self.assertNotIn('CHK13',{t['rule_id'] for t in report['tests']})

    async def test_request_refuses_undeclared_rbac_resource(self):
        shop=RbacShop('fixed')
        async with AccountSessions(project(),dict(PROFILE,max_requests=6),shop.transport) as sess:
            with self.assertRaises(SessionError):await sess.request('a','/api/rbac/staff-report')
            with self.assertRaises(SessionError):await sess.request('a','/api/rbac/../admin')
