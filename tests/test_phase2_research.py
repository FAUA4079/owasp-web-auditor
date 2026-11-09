"""Offline integrity checks for research traceability; no external downloads."""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rows():
    with (ROOT/'research/chk01_chk12_traceability.csv').open(newline='') as f:
        return list(csv.DictReader(f))


def test_twelve_distinct_rules_with_existing_paths():
    rr=rows()
    assert len(rr)==12
    assert {r['chk_id'] for r in rr}=={f'CHK{i:02d}' for i in range(1,13)}
    assert all((ROOT/r['implementation_path']).is_file() for r in rr)


def test_no_fabricated_exact_requirement_ids():
    assert all(not r['asvs_exact_requirement'] and not r['cwe_exact_id'] for r in rows())


def test_versioned_wstg_links_and_ids():
    for r in rows():
        assert r['reference_url'].startswith('https://wstg.owasp.org/v4.2/')
        assert all(v.startswith('WSTG-v42-') for v in filter(None,r['wstg_v42_scenario'].split(';')))


def test_source_versions_and_no_fake_dataset_claims():
    manifest=json.loads((ROOT/'research/source_manifest.json').read_text())
    by_key={s['key']:s for s in manifest['sources']}
    assert by_key['WSTG']['version']=='4.2'
    assert by_key['ASVS']['version']=='5.0.0'
    assert by_key['CWE']['version']=='5.0'
    assert not manifest['imports']


def test_reflection_is_not_confirmed_xss():
    row=next(r for r in rows() if r['chk_id']=='CHK07')
    assert row['relationship']=='preliminary_step_only'
    assert 'never report confirmed XSS' in row['limitations']


def test_local_import_tool_is_available():
    assert (ROOT/'tools/research_dataset.py').is_file()
