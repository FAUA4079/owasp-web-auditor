"""Exercise the real CLI over a loopback TCP socket (not mocked HTTP)."""
import tempfile
from pathlib import Path

from tools.phase4_e2e import execute, SCENARIOS


def test_e2e_full_cli_and_integrity():
    with tempfile.TemporaryDirectory(prefix='owa-e2e-pytest-') as folder:
        result = execute(Path(folder))
        assert result['test_cases'] == len(SCENARIOS) == 5
        assert result['assertions'] == result['assertions_passed'] == 19
        assert result['failed_assertions'] == 0
        assert result['third_party_dataset_cases'] == 0
        assert all(c['tampering_detected'] and c['html_report_generated']
                   and c['evidence_integrity_valid'] and c['json_schema_valid']
                   and not c['ai_used_for_classification'] for c in result['cases'])
        assert (Path(folder)/'e2e_results.json').exists()
        assert (Path(folder)/'e2e_report.md').exists()
