"""Deterministic metadata registry. Never executes detection logic or remote content."""
from functools import lru_cache
from importlib import resources
from json import loads
from types import MappingProxyType
from jsonschema import Draft202012Validator

IDS = tuple(f"CHK{i:02d}" for i in range(1, 14))


def _metadata_directory():
    return resources.files("auditor.rules").joinpath("metadata")


def _deep_freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({k: _deep_freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_deep_freeze(v) for v in value)
    return value


@lru_cache(maxsize=1)
def _load():
    schema = loads(resources.files("auditor.rules").joinpath("schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    data = {}
    for check_id in IDS:
        record = loads(_metadata_directory().joinpath(check_id + ".json").read_text(encoding="utf-8"))
        validator.validate(record)
        if record["id"] != check_id:
            raise ValueError("Mismatched rule ID " + check_id)
        expected_mode = "auditshop_authenticated" if int(check_id[3:]) >= 9 else None
        if expected_mode and record["execution_mode"] != expected_mode:
            raise ValueError("Incorrect authenticated mode for " + check_id)
        if not expected_mode and record["execution_mode"] == "auditshop_authenticated":
            raise ValueError("Incorrect public mode for " + check_id)
        data[check_id] = _deep_freeze(record)
    actual = {entry.name for entry in _metadata_directory().iterdir() if entry.name.endswith(".json")}
    if actual != {i + ".json" for i in IDS}:
        raise ValueError("Metadata inventory does not match supported CHK IDs")
    return MappingProxyType(data)


def get_rule(check_id):
    return _load()[check_id]


def list_rules():
    return tuple(_load()[key] for key in IDS)


def public_rule_ids():
    return IDS[:8]


def authenticated_rule_ids():
    return IDS[8:]


def validate_registry():
    """Fail closed on invalid local rule metadata; no network or AI calls."""
    return len(_load())
