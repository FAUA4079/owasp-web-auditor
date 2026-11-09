import asyncio
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import httpx
from auditor.planning.selection import select_checks
from auditor.resume_engine import run_scan, read_checkpoint
from auditor.verification.integrity import audit_run
from auditor.reporting.html_report import render_report

PROFILE = {'profile_name':'selection-test','max_requests':30,
 'request_timeout_seconds':2,'scan_deadline_seconds':60,'max_response_bytes':4096,
 'max_depth':2,'max_redirects':3,'verify_tls':True}
REAL_CLIENT=httpx.AsyncClient

class Body(httpx.AsyncByteStream):
 def __init__(self,data):self.data=data
 async def __aiter__(self):yield self.data

class SelectionTests(unittest.IsolatedAsyncioTestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.output=Path(self.temp.name)
 async def scan(self, handler, **kwargs):
  def factory(*args,**options):
   options['transport']=httpx.MockTransport(handler)
   return REAL_CLIENT(*args,**options)
  with patch('auditor.core.http_client.httpx.AsyncClient',side_effect=factory),contextlib.redirect_stdout(io.StringIO()):
   return await run_scan('http://lab.example/start.html',PROFILE,self.output,'test',**kwargs)
 def response(self,request):
  return httpx.Response(200,headers={'content-type':'text/html'},stream=Body(b'<a href="/next.html">Next</a>'))
 def read(self,run,name):return json.loads((run/name).read_text())
 def test_selection_validation(self):
  self.assertEqual(select_checks('chk03, CHK02,CHK03'),['CHK02','CHK03'])
  self.assertEqual(len(select_checks()),8)
  self.assertEqual(len(select_checks('all')),8)
  for value in ('','CHK99','CHK02,','CHK07','CHK08','all,CHK02'):
   with self.assertRaises(ValueError):select_checks(value)
  with self.assertRaisesRegex(ValueError,'conflicts'):select_checks('CHK02',reflection='q')
 async def test_selected_header_integrity_and_coverage(self):
  calls=[]
  def handler(r):calls.append(r);return self.response(r)
  run=await self.scan(handler,checks='CHK03',crawl=False)
  self.assertEqual(len(calls),1)
  tests=self.read(run,'results/tests.json')
  self.assertEqual(len(tests),8)
  self.assertEqual({t['rule_id'] for t in tests if t['status']!='Not Tested'},{'CHK03'})
  self.assertEqual({f['rule_id'] for f in self.read(run,'results/findings.json')},{'CHK03'})
  self.assertEqual(audit_run(run),[])
  self.assertEqual(self.read(run,'scan.json')['selected_checks'],['CHK03'])
  self.assertIn('Scan policy',render_report(run))
  plan=self.read(run,'results/plan.json')
  self.assertTrue(all(x['selection']=='not_selected' for x in plan['checks'] if x['rule_id']!='CHK03'))
 async def test_no_crawl_inventories_without_fetching_children(self):
  calls=[]
  def handler(r):calls.append(r.url.path);return self.response(r)
  run=await self.scan(handler,checks='CHK02,CHK03',crawl=False)
  self.assertEqual(calls,['/start.html'])
  inv=self.read(run,'discovery/endpoints.json')
  self.assertEqual(inv['records'][0]['crawl_reason'],'crawling_disabled')
  self.assertEqual(inv['limits_reached'],[])
 async def test_selected_checks_apply_to_crawled_pages(self):
  calls=[]
  def handler(r):calls.append(r.url.path);return self.response(r)
  run=await self.scan(handler,checks='CHK03')
  self.assertEqual(calls,['/start.html','/next.html'])
  tests=self.read(run,'results/tests.json')
  self.assertEqual(len([t for t in tests if t['rule_id']=='CHK03']),2)
  self.assertEqual(len([t for t in tests if t['rule_id']=='CHK02']),1)
  self.assertEqual(audit_run(run),[])
 async def test_probe_only_avoids_unneeded_page_fetch(self):
  calls=[]
  def handler(r):
   calls.append(r)
   return httpx.Response(200,headers={'content-type':'text/plain'},stream=Body(r.url.params.get('q','').encode()))
  run=await self.scan(handler,checks='CHK07',reflection_param='q')
  self.assertEqual(len(calls),2)
  self.assertTrue(all('q' in r.url.params for r in calls))
  self.assertEqual(self.read(run,'discovery/endpoints.json')['reason'],'page_inspection_not_selected')
  self.assertEqual(audit_run(run),[])
 async def test_invalid_selection_creates_no_run(self):
  with self.assertRaises(ValueError):await self.scan(lambda r:self.fail('Unexpected request'),checks='CHK08')
  self.assertEqual(list(self.output.iterdir()),[])
 async def test_resume_preserves_selection_and_rejects_override(self):
  def first(r):
   if r.url.path=='/next.html':raise asyncio.CancelledError()
   return self.response(r)
  with self.assertRaises(asyncio.CancelledError):await self.scan(first,checks='CHK03')
  run=next(self.output.glob('scan-*'))
  before=read_checkpoint(run)
  self.assertEqual(before['selected_checks'],['CHK03'])
  with self.assertRaisesRegex(ValueError,'preserves'):await self.scan(self.response,resume_dir=run,checks='CHK02')
  await self.scan(self.response,resume_dir=run)
  after=read_checkpoint(run)
  self.assertEqual(after['selected_checks'],['CHK03'])
  self.assertTrue(after['complete']);self.assertEqual(audit_run(run),[])
 async def test_network_failure_only_records_selected_response_checks(self):
  def handler(r):raise httpx.ConnectError('down')
  run=await self.scan(handler,checks='CHK03',crawl=False)
  tests=self.read(run,'results/tests.json')
  self.assertEqual(len(tests),8)
  self.assertEqual(next(t for t in tests if t['rule_id']=='CHK02')['reason'],'Disabled by operator check selection.')
  self.assertIn('No complete response',next(t for t in tests if t['rule_id']=='CHK03')['reason'])
 def test_list_checks_needs_no_target_or_ai(self):
  from auditor.__main__ import main
  out=io.StringIO()
  with patch('sys.argv',['auditor','--list-checks']),contextlib.redirect_stdout(out),patch('auditor.reporting.ai.run_scan_with_ai') as runner:
   main();runner.assert_not_called()
  self.assertIn('CHK08',out.getvalue())
