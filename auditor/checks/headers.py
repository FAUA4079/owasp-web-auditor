from datetime import datetime, timezone
from uuid import uuid4


def make_result(rule_id, title, status, reason, observed, evidence_id):
    return {
        "id": f"test-{uuid4().hex[:12]}",
        "rule_id": rule_id,
        "rule_version": "0.1.0",
        "category": "A02:2025",
        "title": title,
        "status": status,
        "reason": reason,
        "steps": ["Inspect the final fetched response headers."],
        "expected": (
            "Relevant response protection is configured "
            "for the response context."
        ),
        "observed": observed,
        "request_count": 0,
        "evidence_refs": [evidence_id],
        "limitations": [
            "Only one fetched response is assessed.",
            "Header presence does not prove policy effectiveness.",
            "Browser exploitation is not attempted.",
        ],
    }


def review_headers(response):
    headers = response["headers"]
    content_type = headers.get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()

    is_html = media_type in {
        "text/html",
        "application/xhtml+xml",
    }

    # Only enforced CSP is considered, not Report-Only.
    policies = headers.get_list("content-security-policy")
    frame_ancestors_present = any(
        directive.strip().split(None, 1)[0].lower()
        == "frame-ancestors"
        for policy in policies
        for directive in policy.split(";")
        if directive.strip()
    )

    xfo_values = headers.get_list("x-frame-options")
    xfo_recognized = (
        len(xfo_values) == 1
        and xfo_values[0].strip().lower() in {"deny", "sameorigin"}
    )

    nosniff_values = headers.get_list("x-content-type-options")
    nosniff = (
        len(nosniff_values) == 1
        and nosniff_values[0].strip().lower() == "nosniff"
    )

    observations = {
        "http_status": response["status_code"],
        "content_type_present": bool(content_type.strip()),
        "declared_html": is_html,
        "frame_ancestors_present": frame_ancestors_present,
        "x_frame_options_present": bool(xfo_values),
        "x_frame_options_recognized": xfo_recognized,
        "nosniff_recognized": nosniff,
    }

    evidence_id = f"ev-{uuid4().hex[:12]}"
    evidence = {
        "id": evidence_id,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "kind": "header_configuration_metadata",
        "observation": observations,
        "body_retained": False,
        "raw_headers_retained": False,
    }

    if not is_html:
        framing_status = "Not Tested"
        framing_reason = (
            "The response is not declared as HTML; "
            "this framing rule was not applied."
        )
    elif frame_ancestors_present or xfo_recognized:
        framing_status = "Inconclusive"
        framing_reason = (
            "A framing policy indicator is present. "
            "This rule version does not validate its effective "
            "restrictions or browser behaviour."
        )
    else:
        framing_status = "Potential"
        framing_reason = (
            "No frame-ancestors directive or recognized "
            "X-Frame-Options policy was observed on the HTML response. "
            "Exploitable clickjacking is not established."
        )

    if not content_type.strip() or not nosniff:
        content_status = "Potential"
        content_reason = (
            "Content-Type is absent or a single valid nosniff header "
            "was not observed. Executable content sniffing "
            "has not been demonstrated."
        )
    else:
        content_status = "No Issue Observed"
        content_reason = (
            "Content-Type and nosniff are present. "
            "MIME correctness and browser behaviour were not verified."
        )

    tests = [
        make_result(
            "CHK02",
            "Framing policy presence",
            framing_status,
            framing_reason,
            observations,
            evidence_id,
        ),
        make_result(
            "CHK03",
            "Content type protection configuration",
            content_status,
            content_reason,
            observations,
            evidence_id,
        ),
    ]

    fixes = {
        "CHK02": (
            "Define an appropriate framing policy for this page. "
            "Validate frame-ancestors and any X-Frame-Options "
            "configuration against intended embedding behaviour."
        ),
        "CHK03": (
            "Return the correct Content-Type and "
            "X-Content-Type-Options: nosniff where appropriate."
        ),
    }

    findings = []

    for test in tests:
        if test["status"] != "Potential":
            continue

        findings.append({
            "id": f"finding-{uuid4().hex[:12]}",
            "rule_id": test["rule_id"],
            "category": test["category"],
            "title": test["title"],
            "status": "Potential",
            "severity": "Informational",
            "confidence": "Configuration observation only",
            "impact": test["reason"],
            "fix": fixes[test["rule_id"]],
            "retest": (
                "Fetch this endpoint again after the change and "
                "review the relevant headers and browser context."
            ),
            "contributing_tests": [test["id"]],
            "evidence_refs": [evidence_id],
        })

    evidence["test_ids"] = [test["id"] for test in tests]
    return tests, evidence, findings


def skipped_header_tests(reason):
    tests = []

    for rule_id, title in (
        ("CHK02", "Framing policy presence"),
        ("CHK03", "Content type protection configuration"),
    ):
        result = make_result(
            rule_id, title, "Not Tested", reason, None, ""
        )
        result["steps"] = []
        result["evidence_refs"] = []
        tests.append(result)

    return tests
