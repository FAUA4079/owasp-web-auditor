"""Local deterministic source manifests and optional privacy-oriented HTML exports.

Manifests detect later byte changes; they are not signed and do not establish
original authenticity. The privacy export does not modify forensic sources.
"""
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from auditor.reporting.validation import load_report_data

CORE = ('scan.json', 'results/tests.json', 'results/findings.json',
        'results/coverage.json', 'results/integrity.json')
MANIFEST = 'results/phase6_source_manifest.json'
_SENSITIVE_KEY = re.compile(r'(?i)(?:password|passwd|secret|authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|session|cookie|private_marker|credential)')
_REDACTED = '[REDACTED]'


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(run):
    run = Path(run).resolve(strict=True)
    load_report_data(run)  # validate source schemas before recording their bytes
    files = [p for rel in CORE if (p := run / rel).is_file()]
    files += sorted((run / 'evidence').glob('*.json'))
    result = {}
    for item in files:
        if item.is_symlink() or not item.resolve().is_relative_to(run):
            raise ValueError('Unsafe evidence/source path')
        result[item.relative_to(run).as_posix()] = _hash(item)
    return {'schema_version': 1, 'algorithm':'sha256', 'scope': 'deterministic source bytes; excludes AI and HTML',
            'files': result}


def save_manifest(run):
    from auditor.scanner import save_json
    manifest = snapshot(run)
    path = Path(run) / MANIFEST
    if path.is_symlink():
        raise ValueError('Symlink manifest destination')
    save_json(path, manifest)
    return manifest


def verify_manifest(run):
    run = Path(run).resolve(strict=True)
    path = run / MANIFEST
    if path.is_symlink() or not path.is_file():
        return False
    try:
        expected = json.loads(path.read_text(), object_pairs_hook=_unique)
        return expected == snapshot(run)
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _unique(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError('duplicate key')
        obj[k] = v
    return obj


def _url(value):
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            return value
        host = parts.hostname or ''
        if parts.port is not None:
            host += ':' + str(parts.port)
        query = urlencode([(k, _REDACTED if _SENSITIVE_KEY.search(k) else v)
                           for k,v in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme,host,parts.path,query,''))
    except ValueError:
        return _REDACTED


def redact(value, key=''):
    """Best-effort export masking; not a guarantee for arbitrary sensitive prose."""
    # 'sessions' is a report history container, not a session token. Preserve
    # its list/dict structure so Jinja can render resume history. Nested
    # session_id, cookie, authorization, etc. remain redacted recursively.
    if key == 'sessions' and isinstance(value, list):
        return [redact(item) for item in value]
    if _SENSITIVE_KEY.search(key):
        return _REDACTED
    if isinstance(value, dict):
        return {k: redact(v,k) for k,v in value.items()}
    if isinstance(value, list):
        return [redact(v,key) for v in value]
    if not isinstance(value, str):
        return value
    value = re.sub(r'(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}={0,2}', '[REDACTED AUTH]', value)
    value = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[REDACTED EMAIL]', value)
    value = re.sub(r'(?i)(\b(?:password|api[_-]?key|token|secret)\s*[:=]\s*)([^\s,;&]+)', r'\1[REDACTED]', value)
    value = re.sub(r'https?://[^\s<>"\']+', lambda m: _url(m.group(0)), value)
    return value
