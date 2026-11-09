from datetime import datetime, timezone
from uuid import uuid4

from auditor.checks.error_disclosure import review_error_disclosure
from auditor.core.http_client import ScanStopped


def skipped_exceptional(target):
    return {
        "id": f"test-{uuid4().hex[:12]}",
        "rule_id": "CHK08",
        "rule_version": "0.1.0",
        "category": "A10:2025",
        "title": "Numeric input error handling",
        "endpoint": target,
        "status": "Not Tested",
        "reason": "No numeric read-only query parameter was selected.",
        "steps": [],
        "expected": (
            "A malformed numeric input is rejected without "
            "exposing internal error details."
        ),
        "observed": None,
        "request_count": 0,
        "evidence_refs": [],
        "limitations": [
            "Only one parameter and one malformed value are tested.",
            "The operator must select an input expected to be numeric.",
            "Baseline value 1 may not be valid for every application.",
            "A 5xx response does not prove injection or availability impact.",
            "Only CHK05-supported disclosure patterns are inspected.",
            "Redirects are not followed.",
        ],
    }


async def review_exceptional(client, target, parameter):
    test = skipped_exceptional(target)
    before_requests = client.request_count

    observed = {
        "parameter": parameter,
        "baseline_status": None,
        "probe_status": None,
        "baseline_error_indicators": [],
        "probe_error_indicators": [],
        "new_error_indicator_types": [],
        "disclosure_inspection_supported": False,
        "stop_reason": None,
    }

    test["status"] = "Inconclusive"
    test["reason"] = "The comparison did not complete."

    try:
        test["steps"].append("Request numeric baseline value 1.")
        baseline = await client.fetch_query_probe(
            target, parameter, "1"
        )
        observed["baseline_status"] = baseline["status_code"]

        if baseline["location"] is not None:
            raise ScanStopped("baseline_redirect_not_followed")

        if not 200 <= baseline["status_code"] < 300:
            raise ScanStopped("baseline_not_successful")

        test["steps"].append("Request one bounded nonnumeric value.")
        probe = await client.fetch_query_probe(
            target, parameter, "AUDITOR_INVALID_INTEGER"
        )
        observed["probe_status"] = probe["status_code"]

        if probe["location"] is not None:
            raise ScanStopped("probe_redirect_not_followed")

        baseline_check, _, _ = review_error_disclosure(baseline)
        probe_check, _, _ = review_error_disclosure(probe)

        baseline_signatures = baseline_check["observed"]["signatures"]
        probe_signatures = probe_check["observed"]["signatures"]

        observed["baseline_error_indicators"] = baseline_signatures
        observed["probe_error_indicators"] = probe_signatures

        baseline_types = {item["type"] for item in baseline_signatures}
        probe_types = {item["type"] for item in probe_signatures}
        new_types = sorted(probe_types - baseline_types)

        observed["new_error_indicator_types"] = new_types

        supported = all(
            check["status"] in {"Potential", "No Issue Observed"}
            and not check["observed"]["text_inspection_limited"]
            and not check["observed"]["signature_limit_reached"]
            for check in (baseline_check, probe_check)
        )
        observed["disclosure_inspection_supported"] = supported

        test["steps"].append(
            "Compare response statuses and redacted error indicators."
        )

        if new_types:
            test["status"] = "Potential"
            test["reason"] = (
                "A new supported error-disclosure indicator type "
                "appeared after the malformed input. Runtime context "
                "and security impact require review."
            )
        elif 500 <= probe["status_code"] < 600:
            test["status"] = "Potential"
            test["reason"] = (
                "The baseline succeeded but the malformed input "
                "received a server-error response. This does not "
                "establish injection, exploitation or a service outage."
            )
        elif (
            400 <= probe["status_code"] < 500
            and supported
            and not baseline_signatures
            and not probe_signatures
        ):
            test["status"] = "No Issue Observed"
            test["reason"] = (
                "The malformed input received a client-error response "
                "without supported disclosure indicators. This applies "
                "only to this input and the inspected response."
            )
        else:
            test["reason"] = (
                "The responses do not establish a reliable rejection "
                "or failure conclusion for this numeric-input check."
            )

    except ScanStopped as exc:
        observed["stop_reason"] = str(exc)
        test["reason"] = f"Exceptional-input check stopped: {exc}"

    test["observed"] = observed
    test["request_count"] = client.request_count - before_requests

    evidence_id = f"ev-{uuid4().hex[:12]}"
    test["evidence_refs"] = [evidence_id]

    evidence = {
        "id": evidence_id,
        "test_id": test["id"],
        "endpoint": target,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "kind": "exceptional_input_comparison",
        "observation": observed,
        "query_values_retained": False,
        "raw_body_retained": False,
    }

    findings = []

    if test["status"] == "Potential":
        findings.append({
            "id": f"finding-{uuid4().hex[:12]}",
            "rule_id": "CHK08",
            "category": "A10:2025",
            "title": "Malformed numeric input needs error-handling review",
            "status": "Potential",
            "severity": "Informational",
            "confidence": "Single baseline/probe comparison",
            "impact": test["reason"],
            "fix": (
                "Review input validation and exception handling. "
                "Reject invalid numeric input with an appropriate "
                "client-error response and avoid public internal diagnostics."
            ),
            "retest": (
                "Repeat the baseline and malformed-input requests "
                "and review the resulting response and server logs."
            ),
            "affected_endpoints": [target],
            "contributing_tests": [test["id"]],
            "evidence_refs": [evidence_id],
        })

    return test, evidence, findings
