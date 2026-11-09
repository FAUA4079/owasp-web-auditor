"""Run real loopback authenticated CLI pipeline as a pytest integration test."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.phase5_rbac_e2e import run_all

def test_full_authenticated_rbac_cli_e2e(tmp_path):
    report=run_all(tmp_path)
    assert report['passed']==3
    assert report['independent_third_party_cases']==0
    assert all(x['integrity_passed'] and x['unapproved_policy_blocked_pre_network'] for x in report['results'])
