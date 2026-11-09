import re
from datetime import datetime, timezone
from uuid import uuid4

from bs4 import BeautifulSoup


PYTHON_FRAME = re.compile(
    r'File\s+"(?P<path>/[^"\r\n]+|[A-Za-z]:\\[^"\r\n]+)"'
    r',\s+line\s+(?P<line>\d{1,9})'
)

PHP_ERROR = re.compile(
    r'\b(?P<kind>Fatal error|Warning|Parse error):'
    r'[^\r\n]{0,1000}?\s+in\s+'
    r'(?P<path>/[^\r\n]{1,500}?|[A-Za-z]:\\[^\r\n]{1,500}?)'
    r'\s+on line\s+(?P<line>\d{1,9})',
    re.IGNORECASE,
)

MAX_TEXT_CHARS = 200_000
MAX_MATCHES = 10


def review_error_disclosure(response):
    endpoint = response["final_url"]
    media_type = response["headers"].get(
        "content-type", ""
    ).split(";", 1)[0].strip().lower()

    supported = media_type in {
        "text/html",
        "application/xhtml+xml",
        "text/plain",
    }

    signatures = []
    text_limited = False

    if supported:
        # The HTTP client has already bounded the response body.
        text = response["body"].decode("utf-8", errors="replace")

        if media_type in {"text/html", "application/xhtml+xml"}:
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup(["script", "style"]):
                tag.decompose()
            text = soup.get_text(separator=" ")

        text_limited = len(text) > MAX_TEXT_CHARS
        text = text[:MAX_TEXT_CHARS]

        marker = "Traceback (most recent call last):"

        for match in PYTHON_FRAME.finditer(text):
            preceding = text[max(0, match.start() - 4000):match.start()]

            if marker not in preceding:
                continue

            signatures.append({
                "type": "python_traceback_with_absolute_path",
                "redacted_excerpt": (
                    'File "[REDACTED_PATH]", line '
                    + match.group("line")
                ),
                "context": "Python traceback marker observed nearby.",
            })

            if len(signatures) >= MAX_MATCHES:
                break

        for match in PHP_ERROR.finditer(text):
            if len(signatures) >= MAX_MATCHES:
                break

            signatures.append({
                "type": "php_error_with_absolute_path",
                "redacted_excerpt": (
                    match.group("kind")
                    + ": [REDACTED_MESSAGE] in [REDACTED_PATH] on line "
                    + match.group("line")
                ),
            })

    if not supported:
        status = "Not Tested"
        reason = "This rule supports declared HTML and plain-text responses."
    elif signatures:
        status = "Potential"
        reason = (
            "Error structures containing absolute-path indicators "
            "were observed. A live backend disclosure has not been "
            "distinguished from quoted examples or documentation."
        )
    elif text_limited:
        status = "Inconclusive"
        reason = (
            "No supported signature was found in the inspected prefix; "
            "the text inspection limit was reached."
        )
    else:
        status = "No Issue Observed"
        reason = (
            "No supported Python/PHP error signature was observed. "
            "Other error formats were not assessed."
        )

    test_id = f"test-{uuid4().hex[:12]}"
    evidence_id = f"ev-{uuid4().hex[:12]}"

    observation = {
        "http_status": response["status_code"],
        "text_inspection_limited": text_limited,
        "signature_limit_reached": len(signatures) >= MAX_MATCHES,
        "signatures": signatures,
    }

    test = {
        "id": test_id,
        "rule_id": "CHK05",
        "rule_version": "0.1.0",
        "category": "A02:2025",
        "title": "Error disclosure indicators",
        "endpoint": endpoint,
        "status": status,
        "reason": reason,
        "steps": (
            ["Inspect bounded response text for supported error structures."]
            if supported else []
        ),
        "expected": "Public responses do not expose internal error details.",
        "observed": observation,
        "request_count": 0,
        "evidence_refs": [evidence_id],
        "limitations": [
            "Only selected Python and PHP patterns are supported.",
            "Documentation can contain matching examples.",
            "Paths and messages are omitted from evidence.",
            "UTF-8 decoding is used; other encodings may be missed.",
            "HTTP status alone is not vulnerability evidence.",
        ],
    }

    evidence = {
        "id": evidence_id,
        "test_id": test_id,
        "endpoint": endpoint,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "kind": "redacted_error_structure",
        "observation": observation,
        "raw_body_retained": False,
        "note": (
            "Excerpts preserve selected matched structure only. "
            "Paths, error messages and surrounding text are omitted."
        ),
    }

    findings = []

    if status == "Potential":
        findings.append({
            "id": f"finding-{uuid4().hex[:12]}",
            "rule_id": "CHK05",
            "category": "A02:2025",
            "title": "Possible internal error disclosure",
            "status": "Potential",
            "severity": "Informational",
            "confidence": "Pattern evidence; runtime context unverified",
            "impact": reason,
            "fix": (
                "Confirm whether the text is an actual runtime error. "
                "If so, return a generic public error and keep detailed "
                "diagnostics in access-controlled server logs."
            ),
            "retest": (
                "Repeat the relevant request and verify that internal "
                "traceback/path details are absent from the public response."
            ),
            "affected_endpoints": [endpoint],
            "contributing_tests": [test_id],
            "evidence_refs": [evidence_id],
        })

    return test, evidence, findings
