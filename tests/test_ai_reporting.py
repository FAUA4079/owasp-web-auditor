import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,AsyncMock
import httpx
from auditor.reporting import ai
from auditor.reporting.html_report import render_report
TEXT={k:'Review required. <script>bad()</script>' for k in ai.SCHEMA['required']}
REAL_CLIENT=httpx.AsyncClient
class AIReportingTests(unittest.IsolatedAsyncioTestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.run=Path(self.temp.name);(self.run/'results').mkdir()
  self.save('scan.json',dict(id='scan-test',tool_version='test',status='finished',request_count=1,started_at='2026-10-21',ended_at=None,target='https://SECRET.example/PRIVATE'))
  self.test=dict(id='t1',rule_id='CHK08',rule_version='1',category='A10:2025',title='PRIVATE',reason='PRIVATE',expected='PRIVATE',steps=[],status='Potential',limitations=[],evidence_refs=[],request_count=1,observed=dict(parameter='PRIVATE',baseline_status=200,probe_status=500,token='SECRET'))
  self.finding=dict(id='f1',rule_id='CHK08',category='A10:2025',title='PRIVATE',status='Potential',severity='Informational',confidence='PRIVATE',impact='PRIVATE',fix='PRIVATE',retest='PRIVATE',contributing_tests=['t1'],evidence_refs=[],affected_endpoints=['https://SECRET.example/PRIVATE'])
  self.save('results/tests.json',[self.test]);self.save('results/findings.json',[self.finding])
  self.env=patch.dict(os.environ,OWA_AI_ENDPOINT='http://127.0.0.1:11436',OWA_AI_MODEL='qwen3:8b',OWA_AI_LANGUAGE='en',OWA_AI_PROVIDER='ollama');self.env.start();self.addCleanup(self.env.stop)
 def save(self,name,value): (self.run/name).write_text(json.dumps(value))
 def reply(self,r): return httpx.Response(200,json={'done':True,'done_reason':'stop','message':{'content':json.dumps(TEXT)}})
 async def generate(self,handler,force=False):
  def factory(**kwargs): return REAL_CLIENT(transport=httpx.MockTransport(handler),**kwargs)
  with patch('auditor.reporting.ai.httpx.AsyncClient',side_effect=factory),contextlib.redirect_stdout(io.StringIO()): await ai.ensure_ai(self.run,force=force)
 async def test_privacy_escaping_and_unchanged_results(self):
  before={p:p.read_bytes() for p in self.run.rglob('*.json')};calls=[]
  def handler(r):
   calls.append(r);self.assertNotIn('PRIVATE',r.content.decode());self.assertNotIn('SECRET',r.content.decode());return self.reply(r)
  await self.generate(handler)
  self.assertEqual(len(calls),2);self.assertEqual(ai.report_view(self.run)['status'],'complete')
  for p,b in before.items(): self.assertEqual(p.read_bytes(),b)
  self.assertNotIn('<script>bad()</script>',render_report(self.run))
 async def test_cache_and_refresh(self):
  await self.generate(self.reply)
  await self.generate(lambda r:self.fail('Unexpected request'))
  calls=[]
  def handler(r): calls.append(r);return self.reply(r)
  await self.generate(handler,True);self.assertEqual(len(calls),2)
 async def test_zero_findings_summary(self):
  self.save('results/findings.json',[]);await self.generate(self.reply)
  self.assertEqual(set(ai.report_view(self.run)['items']),{'summary'})
 async def test_connection_failure_retains_report(self):
  def handler(r): raise httpx.ConnectError('SECRET')
  await self.generate(handler)
  self.assertEqual(ai.report_view(self.run)['reason'],'model_connection_error')
  self.assertNotIn('SECRET',(self.run/'results/ai.json').read_text())
  self.assertTrue((self.run/'reports/report.html').exists())
 async def test_invalid_output_rejected(self):
  for value in ('not JSON',json.dumps(dict(TEXT,status='Confirmed'))):
   await self.generate(lambda r:httpx.Response(200,json={'done':True,'message':{'content':value}}),True)
   self.assertEqual(ai.report_view(self.run)['status'],'unavailable')
 async def test_truncated_output_rejected(self):
  await self.generate(lambda r:httpx.Response(200,json={'done':True,'done_reason':'length','message':{'content':json.dumps(TEXT)}}))
  self.assertEqual(ai.report_view(self.run)['reason'],'incomplete_model_output')
 async def test_partial_retry_only_missing_item(self):
  calls=[]
  def handler(r):
   calls.append(r)
   if len(calls)==2: raise httpx.ConnectError('down')
   return self.reply(r)
  await self.generate(handler);self.assertEqual(ai.report_view(self.run)['status'],'partial')
  calls.clear();await self.generate(handler);self.assertEqual(len(calls),1)
  self.assertEqual(ai.report_view(self.run)['status'],'complete')
 async def test_source_change_hides_stale_text(self):
  await self.generate(self.reply);self.test['status']='No Issue Observed';self.save('results/tests.json',[self.test])
  self.assertEqual(ai.report_view(self.run)['items'],{})
 async def test_cancel_retains_summary(self):
  calls=[]
  def handler(r):
   calls.append(r)
   if len(calls)==2: raise asyncio.CancelledError()
   return self.reply(r)
  with self.assertRaises(asyncio.CancelledError): await self.generate(handler)
  self.assertEqual(ai.report_view(self.run)['reason'],'generation_interrupted')
  self.assertIn('summary',ai.report_view(self.run)['items'])
 async def test_remote_endpoint_rejected(self):
  with patch.dict(os.environ,OWA_AI_ENDPOINT='https://remote.example'): await self.generate(lambda r:self.fail('Remote request'))
  self.assertEqual(ai.report_view(self.run)['reason'],'invalid_local_endpoint')
 async def test_redirect_not_followed(self):
  calls=[]
  def handler(r): calls.append(r);return httpx.Response(302,headers={'location':'https://remote.example'})
  await self.generate(handler);self.assertEqual(len(calls),1)
  self.assertEqual(ai.report_view(self.run)['reason'],'model_http_error')
 async def test_scan_wrapper_automatically_calls_ai(self):
  with patch('auditor.scanner.run_scan',new_callable=AsyncMock,return_value=self.run),patch('auditor.reporting.ai.ensure_all_ai',new_callable=AsyncMock) as generate:
   await ai.run_scan_with_ai('target');generate.assert_awaited_once_with(self.run)
 async def test_hosted_payload_and_secret_exclusion(self):
  calls=[]
  def handler(r):
   calls.append(r)
   self.assertEqual(str(r.url),'https://api.example/v1/chat/completions')
   self.assertEqual(r.headers['Authorization'],'Bearer TEST_PRIVATE_KEY')
   body=json.loads(r.content)
   self.assertEqual(body['response_format'],{'type':'json_object'})
   self.assertNotIn('PRIVATE',r.content.decode())
   self.assertIn('English only',body['messages'][0]['content'])
   return httpx.Response(200,json={'choices':[{'finish_reason':'stop','message':{'content':json.dumps(TEXT)}}]})
  with patch.dict(os.environ,OWA_AI_PROVIDER='openai-compatible',OWA_AI_ENDPOINT='https://api.example/v1',OWA_AI_MODEL='vendor/model',OWA_AI_API_KEY='TEST_PRIVATE_KEY'):
   await self.generate(handler)
   self.assertEqual(len(calls),2)
   self.assertEqual(ai.report_view(self.run)['status'],'complete')
   for path in self.run.rglob('*'):
    if path.is_file(): self.assertNotIn('TEST_PRIVATE_KEY',path.read_text())
 async def test_missing_key_and_auth_errors(self):
  with patch.dict(os.environ,OWA_AI_PROVIDER='openai-compatible',OWA_AI_ENDPOINT='https://api.example/v1',OWA_AI_MODEL='demo',OWA_AI_KEY_ENV='TEST_AUDITOR_KEY',TEST_AUDITOR_KEY=''):
   await self.generate(lambda r:self.fail('Request without key'))
   self.assertEqual(ai.report_view(self.run)['reason'],'missing_or_invalid_api_key')
   for code,reason in ((401,'api_authentication_failed'),(403,'api_access_denied'),(429,'api_rate_limited')):
    with patch.dict(os.environ,TEST_AUDITOR_KEY='TEST_PRIVATE_KEY'):
     await self.generate(lambda r:httpx.Response(code,text='TEST_PRIVATE_KEY'),True)
     self.assertEqual(ai.report_view(self.run)['reason'],reason)
     self.assertNotIn('TEST_PRIVATE_KEY',(self.run/'results/ai.json').read_text())
 async def test_hosted_rejects_unsafe_endpoints(self):
  for endpoint in ('http://api.example/v1','https://user:pass@api.example/v1','https://api.example/v1?key=secret','https://api.example/v1#secret','https://api.example:0/v1'):
   with patch.dict(os.environ,OWA_AI_PROVIDER='openai-compatible',OWA_AI_ENDPOINT=endpoint):
    await self.generate(lambda r:self.fail('Unsafe endpoint request'))
    self.assertEqual(ai.report_view(self.run)['reason'],'invalid_api_endpoint')
 async def test_hosted_malformed_truncated_and_redirect(self):
  with patch.dict(os.environ,OWA_AI_PROVIDER='openai-compatible',OWA_AI_ENDPOINT='https://api.example/v1',OWA_AI_MODEL='demo',OWA_AI_API_KEY='TEST_KEY'):
   for body in ({'choices':[]},{'choices':[{'finish_reason':'length','message':{'content':json.dumps(TEXT)}}]}, {'choices':[{'finish_reason':'stop','message':{'content':None}}]}):
    await self.generate(lambda r:httpx.Response(200,json=body),True)
    self.assertEqual(ai.report_view(self.run)['status'],'unavailable')
   calls=[]
   def handler(r):
    calls.append(r);return httpx.Response(307,headers={'location':'https://other.example/'})
   await self.generate(handler)
   self.assertEqual(len(calls),1)
 async def test_english_overrides_legacy_language(self):
  with patch.dict(os.environ,OWA_AI_LANGUAGE='bn'):
   self.assertEqual(ai.settings()['language'],'en')
   value=dict(TEXT,explanation='\u09ac\u09be\u0982\u09b2\u09be')
   await self.generate(lambda r:httpx.Response(200,json={'done':True,'message':{'content':json.dumps(value)}}))
   self.assertEqual(ai.report_view(self.run)['reason'],'invalid_model_output')
 async def test_provider_switch_and_ollama_no_key(self):
  await self.generate(self.reply);calls=[]
  def handler(r):
   calls.append(r);return httpx.Response(200,json={'choices':[{'finish_reason':'stop','message':{'content':json.dumps(TEXT)}}]})
  with patch.dict(os.environ,OWA_AI_PROVIDER='openai-compatible',OWA_AI_ENDPOINT='https://api.example/v1',OWA_AI_MODEL='demo',OWA_AI_API_KEY='TEST_KEY'):
   await self.generate(handler)
  self.assertEqual(len(calls),2)
  def local(r):
   self.assertNotIn('authorization',r.headers);return self.reply(r)
  with patch.dict(os.environ,OWA_AI_API_KEY='TEST_KEY'): await self.generate(local)
 def test_cli_configuration(self):
  import argparse
  parser=argparse.ArgumentParser();ai.add_ai_arguments(parser)
  args=parser.parse_args(['--ai-provider','openai-compatible','--ai-endpoint','https://api.example/v1','--ai-model','demo','--ai-key-env','MY_KEY'])
  with patch.dict(os.environ):
   ai.apply_ai_arguments(args);config=ai.settings()
   self.assertEqual(config['provider'],'openai-compatible');self.assertEqual(config['key_env'],'MY_KEY')
  self.assertNotIn('--ai-api-key',parser.format_help())
 async def test_legacy_cache_hidden(self):
  await self.generate(self.reply)
  state=json.loads((self.run/'results/ai.json').read_text());state['version']=1
  self.save('results/ai.json',state)
  self.assertEqual(ai.report_view(self.run)['items'],{})
