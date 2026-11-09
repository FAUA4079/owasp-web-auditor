"""Offline checks: no imported dataset claimed present without user files."""
import csv,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_exact_mapping_has_twelve_unique_rules():
    with (ROOT/'research/phase2_exact_mapping.csv').open(newline='') as f: rows=list(csv.DictReader(f))
    assert len(rows)==13
    assert {r['chk_id'] for r in rows}=={f'CHK{i:02d}' for i in range(1,14)}
    assert all(r['semantic_review'] for r in rows)

def test_dataset_specs_are_not_fake_observations():
    spec=json.loads((ROOT/'research/fixtures/case_specifications.json').read_text())
    assert spec['status']=='UNEXECUTED_SPECIFICATIONS'
    assert len(spec['rules'])==13
    for rule in spec['rules']:
        assert {c['expected_label'] for c in rule['cases']}=={'negative','positive_candidate'}
        assert all(c['fixture_status']=='SPECIFICATION_ONLY' and c['evidence_collected'] is False for c in rule['cases'])

def test_reflection_no_confirmed_xss_mapping():
    with (ROOT/'research/phase2_exact_mapping.csv').open(newline='') as f:rows={r['chk_id']:r for r in csv.DictReader(f)}
    assert not rows['CHK07']['cwe_v5_ids']
    assert 'Never label confirmed XSS' in rows['CHK07']['limitations']

def test_known_asvs_ids_are_versioned_by_filename():
    with (ROOT/'research/phase2_exact_mapping.csv').open(newline='') as f:rows=list(csv.DictReader(f))
    assert all(all(v.startswith('V') for v in filter(None,r['asvs_v5_req_ids'].split(';'))) for r in rows)
