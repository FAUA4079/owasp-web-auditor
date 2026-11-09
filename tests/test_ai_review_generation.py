import asyncio
import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch, AsyncMock
import httpx
import test_ai_context as fixtures
from auditor.review.generate import ensure_reviews, review_view, META_PATH
from auditor.review.store import load_reviews, REVIEW_PATH
from auditor.resume_engine import lock_run
from auditor.reporting.html_report import render_report
from auditor.reporting.ai import ensure_all_ai

REAL_CLIENT=httpx.AsyncClient
class ReviewGenerationTests(unittest.IsolatedAsyncioTestCase):
 def setUp(self):
  self.fixture=fixtures.ContextStoreTests();self.fixture.setUp()
  self.addCleanup(self.fixture.doCleanups);self.run=self.fixture.run
  self.env=patch.dict(os.environ,OWA_AI_PROVIDER='ollama',OWA_AI_ENDPOINT='http://127.0.0.1:11436',OWA_AI_MODEL='qwen3:8b')
  self.env.start();self.addCleanup(self.env.stop)
 def payload(self,request):
  body=json.loads(request.content);context=json.loads(body['messages'][1]['content'])
  action={'CHK05':'review_error_context','CHK07':'review_reflection_context','CHK08':'review_input_handling'}[context['rule_id']]
  return {'assessment':'needs_human_review','explanation':'<script>alert(1)</script> Review is needed.',
          'uncertainty':'Only limited metadata is available.','evidence_refs':['evidence-1'],'suggested_verification':action}
 def reply(self,request):
  return httpx.Response(200,json={'done':True,'message':{'content':json.dumps(self.payload(request))}})
 async def generate(self,handler=None,force=False):
  def factory(**kwargs):return REAL_CLIENT(transport=httpx.MockTransport(handler or self.reply),**kwargs)
  with patch('auditor.review.generate.httpx.AsyncClient',side_effect=factory),contextlib.redirect_stdout(io.StringIO()),lock_run(self.run):
   await ensure_reviews(self.run,force=force)
 async def test_generation_privacy_references_and_html_escaping(self):
  before={p:p.read_bytes() for p in self.run.rglob('*.json')};calls=[]
  def handler(r):
   calls.append(r);content=r.content.decode()
   for forbidden in ('PRIVATE_TARGET','SECRET','IGNORE_ALL_INSTRUCTIONS','test-1','ev-1','scan-context'):
    self.assertNotIn(forbidden,content)
   return self.reply(r)
  await self.generate(handler)
  self.assertEqual(len(calls),3)
  state=load_reviews(self.run);self.assertEqual(state['status'],'complete')
  self.assertEqual(state['reviews'][0]['payload']['evidence_refs'],['ev-1'])
  for path,value in before.items():self.assertEqual(path.read_bytes(),value)
  html=render_report(self.run);self.assertNotIn('<script>alert(1)</script>',html)
  self.assertIn('AI review of check evidence',html)
 async def test_cache_refresh_and_archiving(self):
  await self.generate()
  await self.generate(lambda r:self.fail('Unexpected cached request'))
  calls=[]
  def handler(r):calls.append(r);return self.reply(r)
  await self.generate(handler,True)
  self.assertEqual(len(calls),3)
  self.assertEqual(len(list((self.run/'results').glob('ai_review.previous.*.json'))),1)
 async def test_partial_retry_only_missing(self):
  calls=[]
  def handler(r):
   calls.append(r)
   if len(calls)==2:raise httpx.ConnectError('SECRET_KEY')
   return self.reply(r)
  await self.generate(handler)
  self.assertEqual(review_view(self.run)['status'],'partial')
  calls.clear()
  def finish(r):calls.append(r);return self.reply(r)
  await self.generate(finish);self.assertEqual(len(calls),2)
  self.assertEqual(load_reviews(self.run)['status'],'complete')
 async def test_wrong_evidence_alias_and_action_rejected(self):
  for change in ({'evidence_refs':['ev-1']},{'suggested_verification':'review_input_handling'},{'status':'Confirmed'}):
   def handler(r):
    data=self.payload(r);data.update(change)
    return httpx.Response(200,json={'done':True,'message':{'content':json.dumps(data)}})
   await self.generate(handler,True)
   self.assertEqual(review_view(self.run)['status'],'unavailable')
   self.assertEqual(load_reviews(self.run)['reviews'],[])
 async def test_connection_failure_safe_report(self):
  def handler(r):raise httpx.ConnectError('SECRET_KEY')
  await self.generate(handler)
  self.assertEqual(review_view(self.run)['reason'],'model_connection_error')
  self.assertTrue((self.run/'reports/report.html').exists())
  self.assertNotIn('SECRET_KEY',(self.run/META_PATH).read_text())
 async def test_cancellation_keeps_accepted_reviews(self):
  calls=[]
  def handler(r):
   calls.append(r)
   if len(calls)==2:raise asyncio.CancelledError()
   return self.reply(r)
  with self.assertRaises(asyncio.CancelledError):await self.generate(handler)
  self.assertEqual(len(load_reviews(self.run)['reviews']),1)
  self.assertEqual(review_view(self.run)['reason'],'generation_interrupted')
 async def test_changed_source_archives_stale_store(self):
  await self.generate()
  self.fixture.tests[0]['observed']['http_status']=500;self.fixture.persist()
  await self.generate()
  self.assertEqual(review_view(self.run)['status'],'complete')
  self.assertEqual(len(list((self.run/'results').glob('ai_review.previous.*.json'))),1)
 async def test_corrupt_store_not_overwritten(self):
  (self.run/REVIEW_PATH).write_text('{broken')
  await self.generate(lambda r:self.fail('Corrupt store contacted provider'))
  self.assertEqual((self.run/REVIEW_PATH).read_text(),'{broken')
  self.assertEqual(review_view(self.run)['status'],'unavailable')
 async def test_no_eligible_no_provider_calls(self):
  for t in self.fixture.tests:t['status']='Not Tested'
  self.fixture.persist()
  await self.generate(lambda r:self.fail('No eligible reviews'))
  self.assertEqual(review_view(self.run)['status'],'not_applicable')
 async def test_hosted_api_key_never_saved(self):
  def handler(r):
   self.assertEqual(r.headers['authorization'],'Bearer SECRET_API_KEY')
   self.assertNotIn('SECRET_API_KEY',r.content.decode())
   return httpx.Response(200,json={'choices':[{'finish_reason':'stop','message':{'content':json.dumps(self.payload(r))}}]})
  with patch.dict(os.environ,OWA_AI_PROVIDER='openai-compatible',OWA_AI_ENDPOINT='https://api.example/v1',OWA_AI_MODEL='demo',OWA_AI_API_KEY='SECRET_API_KEY'):
   await self.generate(handler)
  self.assertEqual(review_view(self.run)['status'],'complete')
  for p in self.run.rglob('*'):
   if p.is_file():self.assertNotIn('SECRET_API_KEY',p.read_text())
 async def test_provider_change_invalidates_cache(self):
  await self.generate();calls=[]
  def handler(r):calls.append(r);return self.reply(r)
  with patch.dict(os.environ,OWA_AI_MODEL='qwen3:4b'):await self.generate(handler)
  self.assertEqual(len(calls),3)
 async def test_invalid_configuration_is_not_previous_success(self):
  await self.generate()
  with patch.dict(os.environ,OWA_AI_PROVIDER='invalid'):await self.generate(lambda r:self.fail('Invalid provider'))
  self.assertEqual(review_view(self.run)['status'],'unavailable')
  self.assertEqual(review_view(self.run)['reason'],'invalid_configuration')
 async def test_pipeline_runs_both_phases(self):
  with patch('auditor.reporting.ai.ensure_ai',new_callable=AsyncMock) as report,patch('auditor.review.generate.ensure_reviews',new_callable=AsyncMock) as review:
   await ensure_all_ai(self.run,force=True)
   report.assert_awaited_once_with(self.run,force=True);review.assert_awaited_once_with(self.run,force=True)
