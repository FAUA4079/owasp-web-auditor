import secrets
from datetime import datetime, timezone
from uuid import uuid4

from auditor.core.http_client import ScanStopped


def skipped_reflection(target):
    return {
        "id": f"test-{uuid4().hex[:12]}",
        "rule_id": "CHK07",
        "rule_version": "0.2.0",
        "category": "A05:2025",
        "title": "Harmless query reflection review",
        "endpoint": target,
        "status": "Not Tested",
        "reason": "No read-only query parameter was selected.",
        "steps": [],
        "expected": "Record whether selected input is reflected.",
        "observed": None,
        "request_count": 0,
        "evidence_refs": [],
        "limitations": [
            "Reflection alone does not establish XSS.",
            "Only the explicitly selected parameter is assessed.",
            "Output context is heuristic; browser execution and encoding safety are not validated.",
            "Probe redirects are not followed.",
        ],
    }


async def review_reflection(client, target, parameter):
    test = skipped_reflection(target)
    marker = "AUDITOR_" + secrets.token_hex(12)
    start_count = client.request_count

    observed = {
        "parameter": parameter,
        "baseline_status": None,
        "probe_status": None,
        "marker_in_baseline": None,
        "marker_in_probe": None,
        "stop_reason": None,
        "reflection_context": None,
    }

    test["status"] = "Inconclusive"
    test["reason"] = "The comparison did not complete."
    test["steps"] = []

    try:
        test["steps"].append("Request a baseline query value.")
        baseline = await client.fetch_query_probe(
            target, parameter, "auditor_baseline"
        )
        observed["baseline_status"] = baseline["status_code"]

        if baseline["location"] is not None:
            raise ScanStopped("baseline_redirect_not_followed")

        if not 200 <= baseline["status_code"] < 300:
            raise ScanStopped("baseline_non_success_response")

        test["steps"].append("Request a unique harmless marker.")
        probe = await client.fetch_query_probe(target, parameter, marker)
        observed["probe_status"] = probe["status_code"]

        if probe["location"] is not None:
            raise ScanStopped("probe_redirect_not_followed")

        if not 200 <= probe["status_code"] < 300:
            raise ScanStopped("probe_non_success_response")

        baseline_type = baseline["headers"].get(
            "content-type", ""
        ).split(";", 1)[0].strip().lower()
        probe_type = probe["headers"].get(
            "content-type", ""
        ).split(";", 1)[0].strip().lower()

        if baseline_type != probe_type or probe_type not in {
            "text/html", "text/plain", "application/xhtml+xml",
        }:
            raise ScanStopped("unsupported_or_changed_content_type")

        encoded_marker = marker.encode("ascii")
        observed["marker_in_baseline"] = (
            encoded_marker in baseline["body"]
        )
        observed["marker_in_probe"] = encoded_marker in probe["body"]

        from auditor.review.reflection_context import classify_reflection
        observed["reflection_context"] = classify_reflection(probe["body"], marker, probe_type)
        test["steps"].append("Classify bounded reflection context without retaining response text.")
        test["steps"].append("Compare exact marker presence in both bodies.")

        if observed["marker_in_baseline"]:
            test["reason"] = "Marker unexpectedly appeared in the baseline."
        elif observed["marker_in_probe"]:
            test["status"] = "Potential"
            test["reason"] = (
                "The unique query marker was reflected in the response. "
                "HTML execution or XSS has not been demonstrated."
            )
        else:
            test["status"] = "No Issue Observed"
            test["reason"] = (
                "The exact marker was not observed in the probe response. "
                "Encoded, transformed or stored reflection is not assessed."
            )

    except ScanStopped as exc:
        observed["stop_reason"] = str(exc)
        test["reason"] = f"Reflection comparison stopped: {exc}"

    test["request_count"] = client.request_count - start_count
    test["observed"] = observed

    evidence_id = f"ev-{uuid4().hex[:12]}"
    test["evidence_refs"] = [evidence_id]

    evidence = {
        "id": evidence_id,
        "test_id": test["id"],
        "endpoint": target,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "kind": "query_reflection_comparison",
        "observation": observed,
        "query_values_retained": False,
        "response_body_retained": False,
    }

    findings = []

    if test["status"] == "Potential":
        findings.append({
            "id": f"finding-{uuid4().hex[:12]}",
            "rule_id": "CHK07",
            "category": "A05:2025",
            "title": "Query input reflected in response",
            "status": "Potential",
            "severity": "Informational",
            "confidence": "Exact marker reflection; execution unverified",
            "impact": test["reason"],
            "fix": (
                "Review the output context and apply appropriate encoding. "
                "Legitimate reflected output does not itself require removal."
            ),
            "retest": (
                "Repeat the reflection check and separately verify "
                "context-appropriate output encoding."
            ),
            "affected_endpoints": [target],
            "contributing_tests": [test["id"]],
            "evidence_refs": [evidence_id],
        })

    return test, evidence, findings
