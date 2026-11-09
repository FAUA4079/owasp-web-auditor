import asyncio
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import httpx
from test_project_sessions import PROJECT, PROFILE, CREDENTIALS, response
from auditor.auth.assessment import run_assessment
from auditor.auth.project import load_project, ProjectError
from auditor.auth.checks import METADATA
from auditor.reporting.validation import load_report_data
from auditor.verification.integrity import audit_run
from auditor.review.context import build_context, load_context
from auditor.review.store import load_reviews, ReviewError
from auditor.reporting.ai import ensure_all_ai
from auditor.resume_engine import lock_run

REAL_CLIENT=httpx.AsyncClient


def config():
    value=copy.deepcopy(PROJECT)
    value['assessment']={'order_resources':[{'order_id':1001,'owner':'a','other':'b'}]}
    return value


class Shop:
    def __init__(self, scenario='fixed'):
        self.scenario=scenario;self.revoked=set();self.orders=0;self.requests=[]
    def transport(self,alias):return httpx.MockTransport(self.handle)
    def handle(self,r):
        self.requests.append(r)
        cookie=r.headers.get('cookie','')
        actor='a' if 'AUTH_a' in cookie else ('b' if 'AUTH_b' in cookie else None)
        valid=actor is not None and actor not in self.revoked
        path=r.url.path
        if path=='/api/csrf':return response({'csrf_token':'TOKEN'},headers={'set-cookie':'session=ANON; Path=/'})
        if path=='/api/login':
            body=json.loads(r.content);actor='a' if body['email'].startswith('a@') else 'b'
            if self.scenario=='login_failure':return response({},401)
            return response({'csrf_token':'TOKEN'},headers={'set-cookie':'session=AUTH_'+actor+'; Path=/'})
        if path=='/api/me':
            if not valid:return response({},401)
            return response({'id':101 if actor=='a' else 102,'role':'customer'})
        if path=='/api/logout':
            if not valid:return response({},401)
            if self.scenario!='revocation':self.revoked.add(actor)
            return response({},204,{'set-cookie':'session=; Max-Age=0; Path=/'})
        if path=='/api/orders/1001':
            self.orders+=1
            if self.scenario=='cancel' and self.orders==2: raise asyncio.CancelledError()
            if self.scenario=='redirect' and actor=='b':return response({},302,{'location':'https://outside.example/'})
            if actor=='a' or (actor=='b' and self.scenario=='idor') or (actor is None and self.scenario=='guest'):
                marker='PRIVATE_SECRET'
                if self.scenario=='unstable' and self.orders>1:marker='CHANGED'
                return response({'order':{'id':1001,'user_id':101,'private_marker':marker}})
            if self.scenario=='misleading200':return response({'order':{'id':999,'user_id':999,'private_marker':'PUBLIC'}})
            return response({},404 if actor else 401)
        if path=='/api/products':
            query=r.url.params.get('search','')
            ids=[201,202] if not query else []
            if self.scenario=='sql' and 'OR 1=1' in query:ids=[201,202,299]
            return response({'count':len(ids),'products':[{'id':i} for i in ids]})
        raise AssertionError(path)


class AuthenticatedAssessmentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.output=Path(self.temp.name)
    async def scan(self,scenario='fixed',profile=None):
        shop=Shop(scenario)
        # The public client uses the same server transport; its cookie jar remains separate.
        def factory(**kwargs):
            kwargs.setdefault('transport',shop.transport('guest'))
            if kwargs['transport'] is None:kwargs['transport']=shop.transport('guest')
            return REAL_CLIENT(**kwargs)
        with patch('httpx.AsyncClient',side_effect=factory),contextlib.redirect_stdout(io.StringIO()):
            run=await run_assessment(config(),profile or dict(PROFILE,max_requests=50),CREDENTIALS,self.output,
                                     transport_factory=shop.transport,generate_ai=False)
        return run,load_report_data(run),shop
    async def test_fixed_controls_report_and_secret_omission(self):
        run,data,shop=await self.scan()
        self.assertEqual([t['status'] for t in data['tests']],['No Issue Observed']*5)
        self.assertEqual(data['findings'],[]);self.assertEqual(audit_run(run),[])
        self.assertEqual(data['scan']['request_count'],25)
        for f in run.rglob('*'):
            if f.is_file():
                for secret in ('PRIVATE_SECRET','AUTH_a','AUTH_b','TOKEN','SECRET_PASSWORD'):
                    self.assertNotIn(secret,f.read_text())
    async def test_idor_requires_matching_private_identity(self):
        _,data,_=await self.scan('idor')
        self.assertEqual(data['tests'][0]['status'],'Confirmed')
        _,data,_=await self.scan('misleading200')
        self.assertEqual(data['tests'][0]['status'],'Inconclusive')
        self.assertEqual(data['findings'],[])
    async def test_guest_disclosure_is_separate(self):
        _,data,_=await self.scan('guest')
        self.assertEqual(data['tests'][0]['status'],'No Issue Observed')
        self.assertEqual(data['tests'][1]['status'],'Confirmed')
    async def test_unstable_owner_control_is_not_confirmed(self):
        _,data,_=await self.scan('unstable')
        self.assertEqual(data['tests'][0]['status'],'Inconclusive')
    async def test_boolean_differential_remains_potential(self):
        _,data,_=await self.scan('sql')
        self.assertEqual(data['tests'][2]['status'],'Potential')
        self.assertTrue(data['tests'][2]['observed']['repeatable_boolean_differential'])
    async def test_logout_replay_confirms_only_same_identity(self):
        _,data,_=await self.scan('revocation')
        self.assertEqual([t['status'] for t in data['tests'][-2:]],['Confirmed']*2)
    async def test_redirect_does_not_send_cookie_offsite(self):
        _,data,shop=await self.scan('redirect')
        self.assertEqual(data['tests'][0]['status'],'Inconclusive')
        self.assertTrue(all(r.url.host=='127.0.0.1' for r in shop.requests))
    async def test_login_failure_skips_authenticated_checks(self):
        _,data,_=await self.scan('login_failure')
        self.assertEqual([t['status'] for t in data['tests']],['Not Tested','Not Tested','No Issue Observed','Not Tested','Not Tested'])
        self.assertEqual(data['scan']['status'],'partial')
    async def test_exhaustion_preserves_valid_partial_report(self):
        run,data,_=await self.scan(profile=dict(PROFILE,max_requests=8))
        self.assertEqual(data['scan']['request_count'],8)
        self.assertEqual(data['scan']['status'],'partial');self.assertEqual(audit_run(run),[])
    async def test_interrupt_preserves_ledger_and_partial_report(self):
        run,data,_=await self.scan('cancel')
        self.assertEqual(data['scan']['status'],'partial')
        self.assertEqual(data['scan']['stop_reason'],'interrupted')
        self.assertFalse(data['scan']['resumable']);self.assertEqual(audit_run(run),[])
    async def test_minimized_context_and_tamper_rejection(self):
        run,_,_=await self.scan('idor')
        state=build_context(run)
        self.assertEqual(len(state['contexts']),5)
        self.assertEqual({r['rule_id'] for r in state['contexts']},set(METADATA))
        text=json.dumps(state)
        for value in ['PRIVATE_SECRET','1001','127.0.0.1','AUTH_a']:
            self.assertNotIn(value,text)
        self.assertEqual(load_context(run),state)
        path=run/'results/ai_context.json';state['contexts'][0]['observations']['private_resource_match']=False
        path.write_text(json.dumps(state))
        with self.assertRaises(ReviewError):load_context(run)
    async def test_ai_both_stages_schema_and_reference_validation(self):
        run,_,_=await self.scan('idor');sent=[]
        def handle(request):
            body=json.loads(request.content);payload=json.loads(body['messages'][1]['content']);sent.append(payload)
            if 'rule_id' in payload:
                value={'assessment':'needs_human_review','explanation':'Review the declared policy.',
                       'uncertainty':'Limited to the configured resources.','evidence_refs':['evidence-1'],
                       'suggested_verification':'none'}
            else:
                value={k:'Review the recorded evidence and scope.' for k in ['explanation','limitations','suggested_fix','retest']}
            return httpx.Response(200,json={'done':True,'message':{'content':json.dumps(value)}})
        def factory(**kwargs):return REAL_CLIENT(transport=httpx.MockTransport(handle),**kwargs)
        with patch.dict(os.environ,OWA_AI_PROVIDER='ollama',OWA_AI_ENDPOINT='http://127.0.0.1:11434',OWA_AI_MODEL='qwen3:8b'),patch('httpx.AsyncClient',side_effect=factory),contextlib.redirect_stdout(io.StringIO()),lock_run(run):
            await ensure_all_ai(run)
        self.assertEqual(load_reviews(run)['status'],'complete')
        self.assertEqual(json.loads((run/'results/ai.json').read_text())['status'],'complete')
        for value in ['PRIVATE_SECRET','1001','127.0.0.1','AUTH_a']:
            self.assertNotIn(value,json.dumps(sent))
        self.assertEqual(audit_run(run),[])


class AssessmentConfigTests(unittest.TestCase):
    def test_undeclared_or_admin_resource_actors_rejected(self):
        for mutate in [lambda p:p['assessment']['order_resources'][0].update(other='missing'),
                       lambda p:p['accounts'][1].update(expected_role='admin'),
                       lambda p:p['assessment']['order_resources'][0].update(order_id=True)]:
            project=config();mutate(project)
            with tempfile.TemporaryDirectory() as d:
                path=Path(d)/'project.json';path.write_text(json.dumps(project))
                with self.assertRaises(ProjectError):load_project(path)
