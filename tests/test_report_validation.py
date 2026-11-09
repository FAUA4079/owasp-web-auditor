import json
import tempfile
import unittest
from pathlib import Path
from bs4 import BeautifulSoup
from auditor.reporting.html_report import render_report, write_report
from auditor.reporting.validation import load_report_data
from auditor.planning.coverage import build_coverage

class ReportValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = Path(self.temp.name)
        (self.run / 'results').mkdir()
        self.scan = {'id':'scan-test','tool_version':'test','status':'finished',
                     'request_count':0,'started_at':'2026-10-20T00:00:00Z','ended_at':None}
        self.save('scan.json', self.scan)
        self.save('results/tests.json', [])
        self.save('results/findings.json', [])
    def save(self, name, value):
        path = self.run / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding='utf-8')
    def test_missing_required_field_rejected(self):
        del self.scan['request_count']
        self.save('scan.json', self.scan)
        with self.assertRaisesRegex(ValueError, 'scan.json.*required'):
            render_report(self.run)
    def test_wrong_type_and_negative_count_rejected(self):
        for value in ('3', -1, True):
            self.scan['request_count'] = value
            self.save('scan.json', self.scan)
            with self.assertRaisesRegex(ValueError, 'request_count'):
                load_report_data(self.run)
    def test_invalid_status_does_not_echo_value(self):
        self.scan['status'] = 'PRIVATE_REJECTED_VALUE'
        self.save('scan.json', self.scan)
        with self.assertRaises(ValueError) as caught:
            render_report(self.run)
        self.assertNotIn('PRIVATE_REJECTED_VALUE', str(caught.exception))
    def test_duplicate_keys_and_nonfinite_numbers_rejected(self):
        for content in ('{"id":"a","id":"b"}', '{"active_seconds":NaN}'):
            (self.run/'scan.json').write_text(content)
            with self.assertRaisesRegex(ValueError,'invalid JSON'):
                render_report(self.run)
    def test_sessions_coverage_and_empty_results_render(self):
        self.scan.update(sessions=[{'started_at':'FIRST','ended_at':'END'},
                                   {'started_at':'SECOND','ended_at':None}],
                         active_seconds=1.25,resumable=True,status='partial')
        self.save('scan.json', self.scan)
        self.save('results/coverage.json',build_coverage([]))
        document=render_report(self.run)
        for text in ('FIRST','SECOND','1.25','A10:2025','No test records were saved',
                     'No findings were recorded','target content may change'):
            self.assertIn(text,document)
    def test_all_untrusted_fields_are_escaped_not_executed(self):
        marker='<img src=x onerror="alert(1)"><script>bad()</script>{{7*7}}'
        self.scan['target']=marker
        self.save('scan.json',self.scan)
        self.save('results/integrity.json',{'status':'FAIL','scope':marker,'limitation':marker,'errors':[marker]})
        evidence={'id':marker,'content_hash':{'algorithm':'sha256','scope':marker,'value':'a'*64},'observation':marker}
        self.save('evidence/ev-test.json',evidence)
        doc=render_report(self.run)
        soup=BeautifulSoup(doc,'html.parser')
        self.assertFalse(soup.find_all(['script','img','iframe']))
        self.assertIn('{{7*7}}',soup.get_text())
        self.assertNotIn(marker,doc)
        self.assertTrue(all(a.get('href','').startswith('#') for a in soup.find_all('a')))
    def test_invalid_optional_file_is_not_silently_skipped(self):
        self.save('results/coverage.json',{'categories':'wrong'})
        with self.assertRaisesRegex(ValueError,'coverage.json'):
            render_report(self.run)
    def test_invalid_input_preserves_existing_report(self):
        path=write_report(self.run)
        original=path.read_bytes()
        self.save('results/tests.json',{})
        with self.assertRaises(ValueError):
            write_report(self.run)
        self.assertEqual(path.read_bytes(),original)
        self.assertEqual(list(path.parent.glob('*.tmp')),[])
