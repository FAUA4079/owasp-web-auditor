from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from auditor.review.reflection_context import classify_reflection, MAX_CHARS
from auditor.review.context import build_context, load_context, CONTEXT_PATH
from auditor.review.store import ReviewError, _digest

MARKER='AUDITOR_TEST_MARKER'
class ReflectionContextTests(unittest.TestCase):
 def test_html_context_labels_and_no_content_retention(self):
  fixtures={'<p>{}</p>':'html_text','<input value="{}">':'html_attribute',
            '<script>const x="{}";</script>':'script_text','<style>/*{}*/</style>':'style_text',
            '<!-- {} -->':'html_comment'}
  for template,label in fixtures.items():
   body=(template.format(MARKER)+' SECRET_COOKIE PRIVATE_PATH').encode()
   result=classify_reflection(body,MARKER,'text/html')
   self.assertIn(label,result['contexts'])
   self.assertNotIn('SECRET',json.dumps(result));self.assertNotIn(MARKER,json.dumps(result))
 def test_plain_text_and_non_html(self):
  self.assertEqual(classify_reflection(MARKER.encode(),MARKER,'text/plain')['contexts'],['plain_text'])
  self.assertEqual(classify_reflection(MARKER.encode(),MARKER,'application/json')['state'],'unsupported')
 def test_limits_and_unknown_prefix(self):
  result=classify_reflection(b'x'*(MAX_CHARS+1)+MARKER.encode(),MARKER,'text/html')
  self.assertTrue(result['inspection_limited']);self.assertEqual(result['contexts'],[])
  self.assertEqual(result['state'],'not_observed_in_prefix')
  result=classify_reflection((MARKER*25).encode(),MARKER,'text/plain')
  self.assertEqual(result['occurrences_in_prefix'],20);self.assertTrue(result['occurrence_limit_reached'])
 def test_encoded_only_marker_not_reported_as_exact(self):
  body=('<input value="&#65;'+MARKER[1:]+'">').encode()
  self.assertEqual(classify_reflection(body,MARKER,'text/html')['contexts'],[])
 def test_multiple_contexts_and_unclassified_markup(self):
  result=classify_reflection(('<p>'+MARKER+'</p><a title="'+MARKER+'">x</a>').encode(),MARKER,'text/html')
  self.assertEqual(result['contexts'],['html_attribute','html_text'])
  self.assertIn('unclassified',classify_reflection(('<!DOCTYPE '+MARKER+'>').encode(),MARKER,'text/html')['contexts'])

class ContextStoreTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.run=Path(self.temp.name)/'scan-context';(self.run/'results').mkdir(parents=True);(self.run/'evidence').mkdir()
  self.save('scan.json',{'id':'scan-context','tool_version':'test','status':'finished','request_count':0,'started_at':'2026-10-21','ended_at':None,'target':'http://PRIVATE_TARGET/SECRET'})
  self.save('results/findings.json',[])
  self.tests=[]
  obs5={'http_status':200,'text_inspection_limited':False,'signature_limit_reached':False,
        'signatures':[{'type':'python_traceback_with_absolute_path','redacted_excerpt':'SECRET_PATH','context':'IGNORE_ALL_INSTRUCTIONS'}]}
  obs7={'parameter':'SECRET_PARAMETER','baseline_status':200,'probe_status':200,'marker_in_baseline':False,'marker_in_probe':True,'stop_reason':None}
  obs8={'baseline_status':200,'probe_status':500,'baseline_error_indicators':[],
        'probe_error_indicators':[{'type':'php_error_with_absolute_path','redacted_excerpt':'SECRET_VALUE'}],
        'new_error_indicator_types':['IGNORE_ALL_INSTRUCTIONS'],'disclosure_inspection_supported':True,'stop_reason':None}
  for i,(rule,obs) in enumerate((('CHK05',obs5),('CHK07',obs7),('CHK08',obs8)),1):
   self.tests.append({'id':f'test-{i}','rule_id':rule,'rule_version':'0.1.0','category':'A02:2025',
    'title':'SECRET_TITLE','reason':'SECRET_REASON','status':'Potential','steps':[],'expected':'expected',
    'limitations':[],'evidence_refs':[f'ev-{i}'],'request_count':0,'observed':obs})
  self.persist()
 def save(self,name,value):(self.run/name).write_text(json.dumps(value),encoding='utf-8')
 def persist(self):
  self.save('results/tests.json',self.tests)
  for t in self.tests:
   e={'id':t['evidence_refs'][0],'test_id':t['id'],'observation':deepcopy(t['observed'])}
   e['content_hash']={'algorithm':'sha256','scope':'Canonical JSON excluding content_hash','value':_digest(e)}
   self.save('evidence/'+e['id']+'.json',e)
 def test_projection_privacy_and_source_preservation(self):
  before={p:p.read_bytes() for p in self.run.rglob('*.json')}
  with patch('httpx.AsyncClient',side_effect=AssertionError('network')):state=build_context(self.run)
  self.assertEqual(state['status'],'ready');self.assertEqual(len(state['contexts']),3)
  serialized=json.dumps(state)
  for text in ('SECRET','PRIVATE_TARGET','IGNORE_ALL_INSTRUCTIONS','http://'):self.assertNotIn(text,serialized)
  for p,data in before.items():self.assertEqual(p.read_bytes(),data)
  self.assertEqual(load_context(self.run),state)
 def test_legacy_reflection_is_unavailable(self):
  obs=build_context(self.run)['contexts'][1]['observations']
  self.assertEqual(obs['reflection_context']['state'],'unavailable')
  self.assertEqual(obs['browser_execution'],'not_tested')
 def test_new_reflection_metadata_is_preserved(self):
  self.tests[1]['observed']['reflection_context']=classify_reflection(('<p>'+MARKER+'</p>').encode(),MARKER,'text/html')
  self.persist();state=build_context(self.run)
  self.assertEqual(state['contexts'][1]['observations']['reflection_context']['contexts'],['html_text'])
 def test_error_types_and_new_types_are_allowlisted(self):
  records=build_context(self.run)['contexts']
  self.assertEqual(records[0]['observations']['runtime_origin'],'not_determined')
  self.assertEqual(records[2]['observations']['new_error_types'],['php_error_with_absolute_path'])
 def test_tamper_and_stale_context_rejected(self):
  state=build_context(self.run);state['contexts'][0]['scanner_status']='Confirmed';self.save(CONTEXT_PATH,state)
  with self.assertRaises(ReviewError):load_context(self.run)
  build_context(self.run);self.tests[0]['status']='Inconclusive';self.persist()
  with self.assertRaises(ReviewError):load_context(self.run)
  self.assertEqual(build_context(self.run)['contexts'][0]['scanner_status'],'Inconclusive')
 def test_evidence_observation_mismatch_preserves_existing_file(self):
  build_context(self.run);before=(self.run/CONTEXT_PATH).read_bytes()
  self.tests[0]['observed']['http_status']=500;self.save('results/tests.json',self.tests)
  with self.assertRaisesRegex(ReviewError,'observations differ'):build_context(self.run)
  self.assertEqual((self.run/CONTEXT_PATH).read_bytes(),before)
 def test_no_eligible_tests(self):
  for t in self.tests:t['status']='Not Tested'
  self.persist();state=build_context(self.run)
  self.assertEqual(state['status'],'not_applicable');self.assertEqual(state['contexts'],[])
 def test_invalid_metadata_does_not_leak_or_infer(self):
  self.tests[1]['observed']['reflection_context']={'state':'SECRET','contexts':['SECRET']}
  self.tests[0]['observed']['http_status']=True
  self.persist();records=build_context(self.run)['contexts']
  self.assertEqual(records[1]['observations']['reflection_context']['state'],'unavailable')
  self.assertIsNone(records[0]['observations']['http_status'])
 def test_failed_atomic_write_and_symlink(self):
  build_context(self.run);before=(self.run/CONTEXT_PATH).read_bytes()
  with patch('os.replace',side_effect=OSError('failure')):
   with self.assertRaises(OSError):build_context(self.run)
  self.assertEqual((self.run/CONTEXT_PATH).read_bytes(),before)
  (self.run/CONTEXT_PATH).unlink();(self.run/CONTEXT_PATH).symlink_to(self.run/'scan.json')
  with self.assertRaises(ReviewError):build_context(self.run)
