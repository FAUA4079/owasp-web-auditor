"""Phase 7.2 adversarial/offline tests: no external HTTP and no Docker required."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

import httpx

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('phase7_2_chk04', ROOT / 'tools/phase7_2_chk04.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

SAMPLE_CSV = b'# test name, category, real vulnerability, cwe, Benchmark version: 1.2\nBenchmarkTest00016,securecookie,false,614\nBenchmarkTest00087,securecookie,true,614\n'

class FakeClient:
    def get(self, url, headers=None):
        if '00016' in url:
            return httpx.Response(200, headers=[('Set-Cookie', 'SomeCookie=test-secret; Path=/; Secure; HttpOnly; SameSite=Strict')], content=b'normal')
        return httpx.Response(200, headers=[('Set-Cookie', 'BenchmarkTest00087=seed-value; Path=/; Secure; SameSite=Strict')], content=b'setup')

    def post(self, url, cookies=None):
        assert cookies is not None
        return httpx.Response(200, headers=[('Set-Cookie', 'SomeCookie=private-test; Path=/; HttpOnly; SameSite=Strict')], content=b'bad cookie')

class Phase72Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'live'
        self.digest = mod.sha(SAMPLE_CSV)
        self.pin = patch.object(mod, 'PINNED_CSV_SHA256', self.digest)
        self.pin.start()
        self.addCleanup(self.pin.stop)
        self.addCleanup(self.tmp.cleanup)

    def create(self):
        provenance = {'container_id': 'test-container', 'image_id': 'test-image',
                      'commit': mod.PINNED_COMMIT, 'csv_sha256': self.digest, 'working_tree_clean': True}
        with patch.object(mod, 'verify_container', return_value=provenance):
            with patch('subprocess.run', return_value=Mock(stdout=SAMPLE_CSV, returncode=0)):
                mod.capture(self.root, ['docker'], 'owa-benchmark', mod.BASE, client=FakeClient())
        return mod.verify(self.root)

    def test_captures_actual_production_chk04_and_pending_review(self):
        manifest = self.create()
        predictions = {x['case_id']: x['prediction']['status'] for x in manifest['observations']}
        self.assertEqual(predictions, {'BenchmarkTest00016': 'No Issue Observed', 'BenchmarkTest00087': 'Potential'})
        results = mod.score(self.root)
        self.assertEqual(results['counts']['PENDING_REVIEW'], 2)
        self.assertEqual(results['counts']['UNEXECUTED'], 13)
        self.assertEqual(results['counts']['TP'], 0)
        self.assertIsNone(results['metrics']['recall'])
        self.assertNotIn('seed-value', json.dumps(manifest))
        self.assertNotIn('private-test', json.dumps(manifest))

    def test_after_human_review_secure_tn_and_vulnerable_abstains(self):
        self.create()
        csv_path = self.root / 'human_review.csv'
        raw = csv_path.read_text()
        csv_path.write_text(raw.replace('PENDING,,,', 'APPROVED,Review Tester,LAB-REVIEW-2026-11-08,'))
        result = mod.score(self.root)
        self.assertEqual(result['counts']['TN'], 1)
        self.assertEqual(result['counts']['ABSTAINED'], 1)
        self.assertEqual(result['counts']['TP'], 0)
        self.assertEqual(result['metrics']['false_positive_rate'], 0.0)
        self.assertIsNone(result['metrics']['precision'])
        self.assertIsNone(result['metrics']['recall'])

    def test_modified_evidence_refused(self):
        self.create()
        p = self.root / 'BenchmarkTest00087.http-evidence.json'
        p.write_text(p.read_text() + '\n')
        with self.assertRaises(mod.EvaluationError):
            mod.verify(self.root)

    def test_modified_detector_hash_refused(self):
        self.create()
        man = self.root / 'collection_manifest.json'
        obj = json.loads(man.read_text())
        obj['chk04_source_sha256'] = '0' * 64
        mod.save_json(man, obj)
        with self.assertRaises(mod.EvaluationError):
            mod.verify(self.root)

    def test_method_change_refused_even_with_recomputed_evidence_hash(self):
        self.create()
        p = self.root / 'BenchmarkTest00087.http-evidence.json'
        obj = mod.read_json(p)
        obj['method'] = 'GET'
        mod.save_json(p, obj)
        manifest_file = self.root / 'collection_manifest.json'
        man = mod.read_json(manifest_file)
        man['observations'][1]['evidence_sha256'] = mod.filehash(p)
        mod.save_json(manifest_file, man)
        with self.assertRaises(mod.EvaluationError):
            mod.verify(self.root)

    def test_invalid_human_review_refused(self):
        self.create()
        p = self.root / 'human_review.csv'
        p.write_text(p.read_text().replace('PENDING,,,', 'APPROVED,,,'))
        with self.assertRaises(mod.EvaluationError):
            mod.score(self.root)

    def test_no_remote_targets(self):
        for url in ['https://localhost:8443', 'http://127.0.0.1:8443', 'https://127.0.0.1:8444',
                    'https://127.0.0.1:8443@evil.example', 'https://127.0.0.1:8443/evil']:
            with self.subTest(url=url):
                with self.assertRaises(mod.EvaluationError):
                    mod.check_local_base(url)

    def test_csv_label_swap_rejected(self):
        with self.assertRaises(mod.EvaluationError):
            mod.source_labels_from_csv(SAMPLE_CSV.decode().replace('00087,securecookie,true', '00087,securecookie,false'))

    def test_raw_header_case_potential_never_confirmed(self):
        resp = FakeClient().post(mod.BASE + mod.CASES['BenchmarkTest00087']['path'], cookies={'BenchmarkTest00087': 'seed-value'})
        item = mod.capture_evidence('POST', mod.BASE + mod.CASES['BenchmarkTest00087']['path'], resp)
        out = mod.evaluate_evidence(item)
        self.assertEqual(out['status'], 'Potential')
        self.assertEqual(out['finding_count'], 1)

if __name__ == '__main__':
    unittest.main()
