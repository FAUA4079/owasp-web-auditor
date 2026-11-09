from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from uuid import uuid4


def review_cookies(response):
    raw_headers = response["headers"].get_list("set-cookie")
    endpoint = response["final_url"]
    test_id = f"test-{uuid4().hex[:12]}"
    evidence_id = f"ev-{uuid4().hex[:12]}"

    observations = []
    parse_errors = 0

    # Bound metadata processing and mark incomplete coverage.
    for index, raw in enumerate(raw_headers[:100], start=1):
        cookie = SimpleCookie()

        try:
            cookie.load(raw)
        except CookieError:
            parse_errors += 1
            continue

        # One Set-Cookie field should describe one cookie.
        if len(cookie) != 1:
            parse_errors += 1
            continue

        morsel = next(iter(cookie.values()))
        same_site = morsel["samesite"].strip().lower()
        secure = bool(morsel["secure"])
        http_only = bool(morsel["httponly"])

        concerns = []

        if not secure:
            concerns.append("secure_attribute_missing")

        if not http_only:
            concerns.append("httponly_attribute_missing")

        if not same_site:
            concerns.append("samesite_not_explicit")
        elif same_site not in {"strict", "lax", "none"}:
            concerns.append("samesite_unrecognized")
        elif same_site == "none" and not secure:
            concerns.append("samesite_none_without_secure")

        observations.append({
            "header_index": index,
            "purpose": "unknown",
            "secure": secure,
            "httponly": http_only,
            "samesite": (
                same_site
                if same_site in {"strict", "lax", "none"}
                else "missing" if not same_site
                else "unrecognized"
            ),
            "domain_attribute_present": bool(morsel["domain"]),
            "path_attribute_present": bool(morsel["path"]),
            "expires_attribute_present": bool(morsel["expires"]),
            "max_age_attribute_present": bool(morsel["max-age"]),
            "concerns": concerns,
        })

    incomplete = parse_errors > 0 or len(raw_headers) > 100
    has_concerns = any(item["concerns"] for item in observations)

    if not raw_headers:
        status = "Not Tested"
        reason = "No Set-Cookie header was observed in this response."
    elif has_concerns:
        status = "Potential"
        reason = (
            "Cookie attribute concerns were observed. Cookie purpose "
            "is unknown; authentication impact is not established."
        )
        if incomplete:
            reason += " Some cookie headers could not be assessed."
    elif incomplete:
        status = "Inconclusive"
        reason = "One or more cookie headers were not fully assessed."
    else:
        status = "No Issue Observed"
        reason = (
            "No concern was found by the supported attribute checks. "
            "Cookie semantics and browser acceptance were not verified."
        )

    observed = {
        "set_cookie_header_count": len(raw_headers),
        "parsed_cookie_count": len(observations),
        "parse_errors": parse_errors,
        "header_limit_reached": len(raw_headers) > 100,
        "cookies": observations,
    }

    test = {
        "id": test_id,
        "rule_id": "CHK04",
        "rule_version": "0.1.0",
        "category": "A02:2025",
        "title": "Cookie configuration observations",
        "endpoint": endpoint,
        "status": status,
        "reason": reason,
        "steps": [
            "Inspect each Set-Cookie field separately.",
            "Record supported attributes without cookie values.",
        ],
        "expected": "Cookie attributes suit the cookie's intended purpose.",
        "observed": observed,
        "request_count": 0,
        "evidence_refs": [evidence_id],
        "limitations": [
            "Cookie purpose and authentication impact are unknown.",
            "Missing HttpOnly can be intentional for script-readable cookies.",
            "Missing SameSite does not establish cross-site exploitability.",
            "Domain/path values and lifetime validity are not evaluated.",
            "Only final fetched responses are inspected, not redirect cookies.",
            "Python parsing is not a browser-equivalent cookie validator.",
            "Cookie names and values are not retained.",
        ],
    }

    evidence = {
        "id": evidence_id,
        "test_id": test_id,
        "endpoint": endpoint,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "kind": "cookie_attribute_metadata",
        "observation": observed,
        "cookie_values_retained": False,
        "raw_headers_retained": False,
    }

    findings = []

    if status == "Potential":
        findings.append({
            "id": f"finding-{uuid4().hex[:12]}",
            "rule_id": "CHK04",
            "category": "A02:2025",
            "title": "Cookie configuration requires contextual review",
            "status": "Potential",
            "severity": "Informational",
            "confidence": "Attribute observation; purpose unknown",
            "impact": reason,
            "fix": (
                "Identify each cookie's purpose. Review Secure, HttpOnly "
                "and SameSite requirements without breaking intended "
                "JavaScript access or cross-site workflows."
            ),
            "retest": (
                "Fetch the endpoint again and verify the intended cookie "
                "attributes and application behaviour."
            ),
            "affected_endpoints": [endpoint],
            "contributing_tests": [test_id],
            "evidence_refs": [evidence_id],
        })

    return test, evidence, findings
