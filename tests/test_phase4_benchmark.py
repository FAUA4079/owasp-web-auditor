"""Phase 4 controlled fixtures validation; no outside network or AI."""
import asyncio
import json
import sys
import tempfile
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from phase4_benchmark import SPEC_PATH, run

class Phase4BenchmarkTests(unittest.TestCase):
    def test_specification_is_12_by_2(self):
        spec=json.loads(SPEC_PATH.read_text())
        self.assertEqual(len(spec['rules']),13)
        ids=[r['chk_id'] for r in spec['rules'] if r['chk_id'] != 'CHK13']
        self.assertEqual(ids,[f'CHK{i:02}' for i in range(1,13)])
        for rule in spec['rules']:
            self.assertEqual(len(rule['cases']),2)
            self.assertEqual({c['expected_label'] for c in rule['cases']},{'negative','positive_candidate'})

    def test_isolated_execution_and_evidence_minimization(self):
        with tempfile.TemporaryDirectory() as tmp:
            asyncio.run(run(Path(tmp)))
            data=json.loads((Path(tmp)/'benchmark_results.json').read_text())
            self.assertEqual(data['metrics']['total'],24)
            self.assertEqual(len({c['case_id'] for c in data['cases']}),24)
            self.assertEqual(data['metrics']['tp']+data['metrics']['fp']+data['metrics']['tn']+data['metrics']['fn']+data['metrics']['abstained'],24)
            self.assertEqual([c['case_id'] for c in data['cases']], [c['id'] for r in json.loads(SPEC_PATH.read_text())['rules'] if r['chk_id'] != 'CHK13' for c in r['cases']])
            self.assertEqual(data['metrics']['abstained'],1)
            self.assertEqual(next(c for c in data['cases'] if c['case_id']=='CHK02-SECURE-01')['observed_check_status'],'Inconclusive')
            data_text=json.dumps(data)
            for forbidden in ('NEVER_REPORT','TEST_ONLY','SECRET_PASSWORD','PRIVATE_SECRET','AUTH_a','AUTH_b'):
                self.assertNotIn(forbidden,data_text)
            self.assertTrue((Path(tmp)/'benchmark_report.md').exists())

if __name__=='__main__':unittest.main()
