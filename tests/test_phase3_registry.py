"""Metadata compliance, provenance and backward-compatible operation."""
import csv
import json
from pathlib import Path
from importlib import resources
from unittest.mock import patch
import pytest
from jsonschema import ValidationError
from auditor.rules import (get_rule, list_rules, public_rule_ids,
                           authenticated_rule_ids, validate_registry)
from auditor.rules.registry import _load
from auditor.planning.coverage import RULES, AUTH_RULES
from auditor.planning.selection import select_checks, TITLES
from auditor.auth.checks import METADATA

ROOT = Path(__file__).resolve().parents[1]


def test_registry_count_order_and_runtime_alignment():
    assert validate_registry() == 13
    assert tuple(r['id'] for r in list_rules()) == tuple(f'CHK{i:02d}' for i in range(1, 14))
    assert public_rule_ids() == tuple(RULES)
    assert authenticated_rule_ids() == tuple(AUTH_RULES)
    for rule in list_rules():
        check_id = rule['id']
        old = RULES.get(check_id) or AUTH_RULES[check_id]
        assert rule['owasp_top10_2025_category'] == old['category']
        assert rule['scope'] == old['scope']
        assert rule['prerequisites'] == old['prerequisites']
        assert rule['title'] == (TITLES[check_id] if check_id in RULES else (METADATA[check_id][1] if check_id in METADATA else 'Role-based authorization'))


def test_registry_exactly_matches_research_traceability_and_does_not_claim_validation():
    with (ROOT / 'research/phase2_exact_mapping.csv').open(newline='') as f:
        rows = {r['chk_id']: r for r in csv.DictReader(f)}
    assert set(rows) == {r['id'] for r in list_rules()}
    for r in list_rules():
        source = rows[r['id']]
        assert list(r['research']['asvs']['requirement_ids']) == list(filter(None, source['asvs_v5_req_ids'].split(';')))
        assert list(r['research']['cwe']['weakness_ids']) == list(filter(None, source['cwe_v5_ids'].split(';')))
        assert r['research']['relationship'] == source['relationship']
        assert r['research']['limitations'] == source['limitations']
        assert r['validation']['ground_truth_status'] == 'UNEXECUTED_SPECIFICATIONS'
        assert r['safety']['executes_code_from_metadata'] is False


def test_registry_is_read_only_and_selection_still_works():
    with pytest.raises(TypeError):
        get_rule('CHK01')['title'] = 'modified'
    with pytest.raises(TypeError):
        get_rule('CHK04')['research']['asvs']['version'] = '0'
    assert select_checks('CHK03,CHK02') == ['CHK02','CHK03']
    assert select_checks('all') == list(public_rule_ids())
    with pytest.raises(ValueError):
        select_checks('CHK09')


def test_schema_rejects_unapproved_execution_fields():
    from jsonschema import Draft202012Validator
    schema = json.loads(resources.files('auditor.rules').joinpath('schema.json').read_text())
    data = json.loads(resources.files('auditor.rules').joinpath('metadata/CHK07.json').read_text())
    data['shell_command'] = 'echo unsafe'
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(data)


def test_wheel_metadata_includes_all_rules():
    assert resources.files('auditor.rules').joinpath('schema.json').is_file()
    assert resources.files('auditor.rules').joinpath('metadata/CHK12.json').is_file()


def test_offline_registry_inspection(capsys):
    from auditor.rules.__main__ import main
    with patch('sys.argv', ['auditor.rules', '--check', 'CHK12', '--json']):
        main()
    result = json.loads(capsys.readouterr().out)
    assert [r['id'] for r in result] == ['CHK12']
    assert result[0]['research']['asvs']['requirement_ids'] == ['V7.4.1']
    with patch('sys.argv', ['auditor.rules', '--validate']):
        main()
    assert 'schema-valid' in capsys.readouterr().out
