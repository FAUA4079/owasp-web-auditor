from contextlib import nullcontext
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import uuid4

from auditor.core.http_client import BoundedHTTPClient, ScanStopped


RULE_ID = "CHK01"
RULE_VERSION = "1.0.0"


async def check_https_handling(target, profile, transport=None, client=None):
    test_id = f"test-{uuid4().hex[:12]}"

    result = {
        "id": test_id,
        "rule_id": RULE_ID,
        "rule_version": RULE_VERSION,
        "category": "A04:2025",
        "title": "HTTP root HTTPS redirect handling",
        "status": "Not Tested",
        "reason": None,
        "steps": [],
        "expected": (
            "The HTTP root redirects within the allowed scope "
            "to a reachable HTTPS response."
        ),
        "observed": None,
        "request_count": 0,
        "evidence_refs": [],
        "limitations": [
            "Only the supplied root and its redirect chain are assessed.",
            "No complete TLS configuration assessment is performed.",
            "No claim is made about sensitive data exposure.",
        ],
    }

    parts = urlsplit(target)

    if parts.scheme != "http":
        result["reason"] = "An HTTP URL is needed to assess HTTP behaviour."
        return result, None, None

    if parts.path not in {"", "/"} or parts.query:
        result["reason"] = "This rule version requires an HTTP root URL."
        return result, None, None

    observation = {
        "initial_scheme": "http",
        "final_scheme": None,
        "final_status_code": None,
        "final_body_bytes": None,
        "stop_reason": None,
    }

    result["steps"] = [
        "Request the supplied HTTP root.",
        "Check scope before following every redirect.",
        "Observe the final scheme and response status.",
    ]

    context = (
        BoundedHTTPClient(target, profile, transport=transport)
        if client is None
        else nullcontext(client)
    )

    async with context as client:
        first_request = client.request_count
        first_record = len(client.ledger)

        try:
            response = await client.fetch(target)

            final_scheme = urlsplit(response["final_url"]).scheme
            final_status = response["status_code"]

            observation.update({
                "final_scheme": final_scheme,
                "final_status_code": final_status,
                "final_body_bytes": len(response["body"]),
            })

            if final_scheme == "https":
                result["status"] = "No Issue Observed"
                result["reason"] = (
                    "The observed HTTP redirect chain reached HTTPS. "
                    "This does not establish application-wide security."
                )

            elif 300 <= final_status < 400:
                result["status"] = "Inconclusive"
                result["reason"] = (
                    "The chain ended with an HTTP 3xx response "
                    "without a supported followable redirect."
                )

            else:
                result["status"] = "Potential"
                result["reason"] = (
                    "The supplied root returned a response over HTTP "
                    "without reaching HTTPS. Sensitive content and "
                    "application impact have not been established."
                )

        except ScanStopped as exc:
            observation["stop_reason"] = str(exc)
            result["status"] = "Inconclusive"
            result["reason"] = (
                f"Retrieval stopped: {exc}. "
                "The redirect assessment is incomplete."
            )

        ledger = list(client.ledger[first_record:])
        result["request_count"] = client.request_count - first_request

    evidence_id = f"ev-{uuid4().hex[:12]}"
    evidence = {
        "id": evidence_id,
        "test_id": test_id,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "kind": "transport_metadata",
        "observation": observation,
        "request_ledger": ledger,
        "body_retained": False,
        "headers_retained": False,
        "note": (
            "Metadata-only evidence. An endpoint may be attached by the runner. "
            "No response body, cookie value or authorization header is retained."
        ),
    }

    result["observed"] = observation
    result["evidence_refs"] = [evidence_id]

    finding = None

    if result["status"] == "Potential":
        finding = {
            "id": f"finding-{uuid4().hex[:12]}",
            "rule_id": RULE_ID,
            "category": "A04:2025",
            "title": "HTTP root did not redirect to HTTPS",
            "status": "Potential",
            "severity": "Informational",
            "confidence": "High for observed transport behaviour",
            "impact": (
                "The observed response used unencrypted HTTP. "
                "Sensitive data exposure was not demonstrated."
            ),
            "fix": (
                "Review whether the HTTP root should redirect to HTTPS. "
                "Configure the redirect where appropriate."
            ),
            "retest": (
                "Repeat this check and confirm the HTTP root reaches "
                "the intended same-host HTTPS destination."
            ),
            "contributing_tests": [test_id],
            "evidence_refs": [evidence_id],
        }

    return result, evidence, finding
