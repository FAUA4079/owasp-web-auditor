from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from auditor.review.store import (initialize, load_reviews, save_review, ReviewError,
                                  REVIEW_PATH, _digest)
from auditor.resume_engine import lock_run

PAYLOAD = {'assessment':'needs_human_review', 'explanation':'A server error alone does not demonstrate injection.',
 'uncertainty':'Only one malformed value was tested.', 'evidence_refs':['ev-one'],
 'suggested_verification':'review_input_handling'}

class ReviewStoreTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.run=Path(self.temp.name)/'scan-demo';(self.run/'results').mkdir(parents=True)
  (self.run/'evidence').mkdir()
  self.scan={'id':'scan-demo','tool_version':'test','status':'finished','request_count':0,
             'started_at':'2026-10-21','ended_at':None}
  self.test={'id':'test-one','rule_id':'CHK08','rule_version':'0.1.0','category':'A10:2025',
   'title':'Input handling','status':'Potential','reason':'Server error','steps':[],
   'expected':'Handled input','limitations':[],'evidence_refs':['ev-one'],'request_count':0}
  self.tests=[self.test];self.save('scan.json',self.scan);self.save('results/tests.json',self.tests)
  self.save('results/findings.json',[])
  self.evidence('ev-one',['test-one'])
 def save(self,name,value): (self.run/name).write_text(json.dumps(value),encoding='utf-8')
 def evidence(self,identifier,owners):
  item={'id':identifier,'test_ids':owners,'kind':'test_metadata'}
  item['content_hash']={'algorithm':'sha256','scope':'Canonical JSON excluding content_hash','value':_digest(item)}
  self.save('evidence/'+identifier+'.json',item)
 def submit(self,payload=None,**kwargs):
  return save_review(self.run,'test-one',deepcopy(PAYLOAD if payload is None else payload),provider='ollama',model='qwen3:8b',**kwargs)
 def test_pending_init_is_idempotent_and_no_network(self):
  with patch('httpx.AsyncClient',side_effect=AssertionError('network')):
   state=initialize(self.run)
   self.assertEqual(state['status'],'pending');self.assertEqual(state['reviews'],[])
   before=(self.run/REVIEW_PATH).read_bytes();initialize(self.run)
   self.assertEqual((self.run/REVIEW_PATH).read_bytes(),before)
 def test_valid_review_stays_separate_and_is_idempotent_by_test(self):
  before={p:p.read_bytes() for p in self.run.rglob('*.json')}
  state=self.submit();self.assertEqual(state['status'],'complete')
  self.assertEqual(state['reviews'][0]['scanner_status'],'Potential')
  self.assertTrue(state['reviews'][0]['review_required'])
  self.submit();self.assertEqual(len(load_reviews(self.run)['reviews']),1)
  for p,data in before.items():self.assertEqual(p.read_bytes(),data)
 def test_extra_status_severity_commands_and_bad_text_rejected(self):
  for patch_value in ({'status':'Confirmed'},{'severity':'Critical'},{'command':'curl target'},
                      {'explanation':''},{'explanation':'x'*2201},{'uncertainty':'\u09ac\u09be\u0982\u09b2\u09be'},
                      {'assessment':'confirmed'}):
   with self.assertRaises(ReviewError):self.submit(dict(PAYLOAD,**patch_value))
  self.assertFalse((self.run/REVIEW_PATH).exists())
 def test_missing_duplicate_unknown_and_path_refs_rejected(self):
  for refs in ([],['ev-one','ev-one'],['ev-missing'],['../../scan.json']):
   with self.assertRaises(ReviewError):self.submit(dict(PAYLOAD,evidence_refs=refs))
 def test_evidence_from_another_test_rejected(self):
  self.tests.append(dict(self.test,id='test-two',evidence_refs=['ev-two']))
  self.save('results/tests.json',self.tests);self.evidence('ev-two',['test-two'])
  with self.assertRaisesRegex(ReviewError,'belong'):self.submit(dict(PAYLOAD,evidence_refs=['ev-two']))
 def test_missing_backlink_rejected(self):
  self.evidence('ev-one',['different-test'])
  with self.assertRaisesRegex(ReviewError,'backlink'):initialize(self.run)
 def test_tampered_evidence_hash_rejected(self):
  path=self.run/'evidence/ev-one.json';item=json.loads(path.read_text());item['kind']='changed'
  self.save('evidence/ev-one.json',item)
  with self.assertRaisesRegex(ReviewError,'hash'):initialize(self.run)
 def test_source_change_rejects_stale_store_without_overwrite(self):
  self.submit();before=(self.run/REVIEW_PATH).read_bytes()
  self.test['reason']='Changed observation';self.save('results/tests.json',self.tests)
  for action in (lambda:initialize(self.run),lambda:load_reviews(self.run),lambda:self.submit()):
   with self.assertRaisesRegex(ReviewError,'stale'):action()
  self.assertEqual((self.run/REVIEW_PATH).read_bytes(),before)
 def test_incorrect_rule_or_status_in_saved_store_rejected(self):
  self.submit();state=json.loads((self.run/REVIEW_PATH).read_text())
  for field,value in (('rule_id','CHK07'),('scanner_status','Confirmed')):
   changed=deepcopy(state);changed['reviews'][0][field]=value;self.save(REVIEW_PATH,changed)
   with self.assertRaises(ReviewError):load_reviews(self.run)
 def test_wrong_followup_and_provider_rejected(self):
  with self.assertRaises(ReviewError):self.submit(dict(PAYLOAD,suggested_verification='review_reflection_context'))
  with self.assertRaises(ReviewError):save_review(self.run,'test-one',PAYLOAD,provider='unknown',model='demo')
 def test_not_tested_and_unsupported_are_not_applicable(self):
  for updates in ({'status':'Not Tested'},{'rule_id':'CHK03'}):
   self.save('results/tests.json',[dict(self.test,**updates)])
   state=initialize(self.run);self.assertEqual(state['status'],'not_applicable')
   with self.assertRaises(ReviewError):self.submit()
   (self.run/REVIEW_PATH).unlink()
 def test_duplicate_source_and_review_ids_rejected(self):
  self.save('results/tests.json',[self.test,self.test])
  with self.assertRaises(ReviewError):initialize(self.run)
  self.save('results/tests.json',[self.test]);self.submit()
  state=json.loads((self.run/REVIEW_PATH).read_text());state['reviews']*=2;self.save(REVIEW_PATH,state)
  with self.assertRaises(ReviewError):load_reviews(self.run)
 def test_partial_and_false_complete_rejected(self):
  self.tests.append(dict(self.test,id='test-two',evidence_refs=['ev-two']))
  self.save('results/tests.json',self.tests);self.evidence('ev-two',['test-two'])
  state=self.submit();self.assertEqual(state['status'],'partial')
  state['status']='complete';self.save(REVIEW_PATH,state)
  with self.assertRaises(ReviewError):load_reviews(self.run)
 def test_malformed_store_never_silently_replaced(self):
  for content in ('{"schema_version":1,"schema_version":1}', '{bad', '{"x":NaN}', 'x'*(4*1024*1024+1)):
   (self.run/REVIEW_PATH).write_text(content)
   with self.assertRaises(ReviewError):initialize(self.run)
   self.assertEqual((self.run/REVIEW_PATH).read_text(),content)
 def test_lock_and_atomic_write_failure(self):
  initialize(self.run);before=(self.run/REVIEW_PATH).read_bytes()
  with lock_run(self.run):
   with self.assertRaises(ValueError):self.submit()
  with patch('os.replace',side_effect=OSError('simulated failure')):
   with self.assertRaises(OSError):self.submit()
  self.assertEqual((self.run/REVIEW_PATH).read_bytes(),before)
  self.assertEqual(list((self.run/'results').glob('.pending-*')),[])
 def test_symlink_destination_rejected(self):
  target=Path(self.temp.name)/'outside.json';target.write_text('untouched')
  (self.run/REVIEW_PATH).symlink_to(target)
  with self.assertRaises(ReviewError):initialize(self.run)
  self.assertEqual(target.read_text(),'untouched')
 def test_evidence_filename_mismatch_rejected(self):
  (self.run/'evidence/ev-one.json').rename(self.run/'evidence/wrong.json')
  with self.assertRaises(ReviewError):initialize(self.run)
