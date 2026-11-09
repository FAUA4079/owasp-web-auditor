import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'tools/phase7_evaluation.py'
spec = importlib.util.spec_from_file_location('phase7_evaluation', SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Phase7EvaluationTests(unittest.TestCase):
    def test_external_labels_verified_and_scored_as_unexecuted(self):
        with tempfile.TemporaryDirectory() as t:
            man = Path(t) / 'manifest.json'
            data = mod.prepare(mod.DEFAULT_DATA, mod.DEFAULT_MAP, man)
            self.assertEqual(data['labels_count'], 15)
            self.assertEqual(len(data['applicability']), 13)
            scored = mod.score(man)
            self.assertEqual(scored['counts']['UNEXECUTED'], 15)
            self.assertIsNone(scored['metrics']['precision'])
            self.assertIsNone(scored['metrics']['recall'])
            self.assertEqual(scored['metrics']['execution_fraction'], 0)

    def test_modified_label_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            man = Path(t) / 'manifest.json'
            mod.prepare(mod.DEFAULT_DATA, mod.DEFAULT_MAP, man)
            payload = json.loads(man.read_text())
            payload['labels'][0]['expected_vulnerability'] = False
            man.write_text(json.dumps(payload))
            with self.assertRaises(mod.EvaluationError):
                mod.score(man)

    def test_invalid_source_label_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            data = Path(t) / 'data.csv'
            data.write_text('BenchmarkTest00001,sqli,maybe,89\n')
            with self.assertRaises(mod.EvaluationError):
                mod.load_labels(data)

    def test_scoring_rejects_unverified_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            man = root / 'manifest.json'
            mod.prepare(mod.DEFAULT_DATA, mod.DEFAULT_MAP, man)
            evidence = root / 'evidence.json'
            evidence.write_text('{"test": 1}')
            obs = root / 'observations.json'
            obs.write_text(json.dumps({'schema_version': 1, 'observations': [{
                'case_id': 'BenchmarkTest00008', 'check_id': 'CHK11',
                'status': 'Confirmed', 'benchmark_endpoint': '127.0.0.1 only',
                'human_review_reference': 'test-only', 'evidence_path': 'evidence.json',
                'evidence_sha256': '0' * 64}]}))
            with self.assertRaises(mod.EvaluationError):
                mod.score(man, obs, root)

    def test_observation_valid_evidence_and_abstention(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            man = root / 'manifest.json'
            mod.prepare(mod.DEFAULT_DATA, mod.DEFAULT_MAP, man)
            evidence = root / 'evidence.json'
            evidence.write_text('{"test": "sample-only"}')
            obs = root / 'observations.json'
            obs.write_text(json.dumps({'schema_version': 1, 'observations': [{
                'case_id': 'BenchmarkTest00008', 'check_id': 'CHK11',
                'status': 'Potential', 'benchmark_endpoint': 'localhost/sample',
                'human_review_reference': 'unit-test-not-a-real-review',
                'evidence_path': 'evidence.json', 'evidence_sha256': mod.digest(evidence)}]}))
            score = mod.score(man, obs, root)
            self.assertEqual(score['counts']['ABSTAINED'], 1)
            self.assertEqual(score['counts']['UNEXECUTED'], 14)
            self.assertIsNone(score['metrics']['precision'])


if __name__ == '__main__':
    unittest.main()
