"""Offline Phase 7.3 safeguards; decisions in tests are synthetic, not real approvals."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

mod = load('phase7_3_review')
p72 = mod.p72
SAMPLE = b'# test name, category, real vulnerability, cwe\nBenchmarkTest00016,securecookie,false,614\nBenchmarkTest00087,securecookie,true,614\n'

class FakeClient:
    def get(self, url, headers=None):
        import httpx
        if '00016' in url:
            return httpx.Response(200, headers=[('Set-Cookie','SomeCookie=secret; Secure; HttpOnly; SameSite=Strict')], content=b'ok')
        return httpx.Response(200, headers=[('Set-Cookie','BenchmarkTest00087=seed-value; Secure')], content=b'init')
    def post(self, url, cookies=None):
        import httpx
        return httpx.Response(200, headers=[('Set-Cookie','SomeCookie=private-value; HttpOnly')], content=b'bad')

class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'live'
        pin = patch.object(p72, 'PINNED_CSV_SHA256', p72.sha(SAMPLE))
        pin.start()
        self.addCleanup(pin.stop)
        att = {'container_id':'test','image_id':'test','commit':p72.PINNED_COMMIT,
               'csv_sha256':p72.sha(SAMPLE),'working_tree_clean':True}
        with patch.object(p72, 'verify_container', return_value=att):
            with patch('subprocess.run', return_value=Mock(stdout=SAMPLE, returncode=0)):
                p72.capture(self.root, ['docker'], 'owa-benchmark', p72.BASE, client=FakeClient())
    def approve(self, case='BenchmarkTest00016'):
        cp = mod.checkpoint(self.root, case)
        return mod.attest(self.root, case, 'APPROVED', 'Independent Reviewer', 'REVIEW-123',
                          'Inspected source and response independently', cp['evidence_sha256'], True)
    def test_packet_redacts_secrets_and_does_not_approve(self):
        content = mod.packet(self.root, self.root / 'packet.md').read_text()
        self.assertNotIn('private-value', content)
        self.assertNotIn('seed-value', content)
        self.assertIn('BenchmarkTest00087', content)
        self.assertEqual(p72.read_reviews(self.root)['BenchmarkTest00016']['review_status'], 'PENDING')
    def test_review_requires_explicit_confirmation(self):
        cp = mod.checkpoint(self.root, 'BenchmarkTest00016')
        with self.assertRaises(mod.ReviewError):
            mod.attest(self.root, 'BenchmarkTest00016', 'APPROVED', 'Reviewer', 'REVIEW-123', 'review', cp['evidence_sha256'], False)
    def test_wrong_digest_refused(self):
        with self.assertRaises(mod.ReviewError):
            mod.attest(self.root, 'BenchmarkTest00016','APPROVED','Reviewer','REVIEW-123','review','0'*64,True)
    def test_approval_audit_and_scoring(self):
        self.approve('BenchmarkTest00016')
        self.assertEqual(mod.audit(self.root)[0][1], 'APPROVED')
        result = p72.score(self.root)
        self.assertEqual(result['counts']['TN'], 1)
        self.assertEqual(result['counts']['PENDING_REVIEW'], 1)
    def test_rejected_case_not_scored(self):
        cp = mod.checkpoint(self.root, 'BenchmarkTest00087')
        mod.attest(self.root,'BenchmarkTest00087','REJECTED','Reviewer','REVIEW-124','Mismatch found',cp['evidence_sha256'],True)
        mod.audit(self.root)
        self.assertEqual(p72.score(self.root)['counts']['REJECTED_REVIEW'], 1)
    def test_edit_review_csv_is_detected(self):
        self.approve()
        f = self.root / 'human_review.csv'
        f.write_text(f.read_text().replace('REVIEW-123','REVIEW-999'))
        with self.assertRaises(mod.ReviewError):
            mod.audit(self.root)
    def test_edit_evidence_detected(self):
        self.approve()
        p = self.root / 'BenchmarkTest00016.http-evidence.json'
        p.write_text(p.read_text()+'\n')
        with self.assertRaises(p72.EvaluationError):
            mod.audit(self.root)
    def test_duplicate_approval_refused(self):
        self.approve()
        with self.assertRaises(mod.ReviewError):
            self.approve()
    def test_pending_approval_without_attestation_refused(self):
        path=self.root/'human_review.csv'
        path.write_text(path.read_text().replace('PENDING,,,','APPROVED,Reviewer,REVIEW-1,',1))
        with self.assertRaises(mod.ReviewError):
            mod.audit(self.root)

if __name__ == '__main__':
    unittest.main()
