"""Check the Phase 1 human-curated research index against the existing registry."""
import csv
import json
from pathlib import Path
import unittest
from auditor.planning.coverage import RULES, AUTH_RULES

ROOT = Path(__file__).resolve().parents[1]

class ResearchTraceabilityTests(unittest.TestCase):
    def test_manifest_has_pinned_sources(self):
        data = json.loads((ROOT / 'research/source_manifest.json').read_text())
        sources = {item['key']: item for item in data['sources']}
        self.assertEqual({key: sources[key]['version'] for key in ('WSTG','ASVS','CWE','TOP10')},
                         {'WSTG':'4.2','ASVS':'5.0.0','CWE':'5.0','TOP10':'2025'})
        for entry in sources.values():
            self.assertTrue(entry['landing_url'].startswith('https://'))

    def test_matrix_matches_registered_checks(self):
        with (ROOT / 'research/chk01_chk12_traceability.csv').open(newline='') as handle:
            rows = list(csv.DictReader(handle))
        registry = {**RULES, **AUTH_RULES}
        self.assertEqual(set(row['chk_id'] for row in rows), set(registry) - {'CHK13'})
        self.assertEqual(len(rows), len(registry) - 1)
        for row in rows:
            with self.subTest(check=row['chk_id']):
                self.assertEqual(row['owasp_top10_2025'], registry[row['chk_id']]['category'])
                self.assertTrue((ROOT / row['implementation_path']).is_file())
                self.assertTrue(row['reference_url'].startswith('https://wstg.owasp.org/v4.2/'))
                self.assertIn(row['relationship'], ('direct_methodology_partial_implementation', 'direct_methodology_lab_specific', 'related_not_equivalent', 'preliminary_step_only', 'no_exact_scenario_verified'))
                self.assertEqual(row['ground_truth_status'], 'not_yet_benchmarked')
