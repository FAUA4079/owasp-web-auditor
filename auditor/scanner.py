import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from auditor.checks.directory_listing import review_directory_listing
from auditor.checks.reflection import review_reflection, skipped_reflection
from auditor.checks.exceptional_input import review_exceptional, skipped_exceptional
from auditor.checks.cookies import review_cookies
from auditor.checks.error_disclosure import review_error_disclosure
from auditor.checks.headers import (
    review_headers,
    skipped_header_tests,
)
from auditor.checks.https_handling import check_https_handling
from auditor.core.http_client import BoundedHTTPClient, ScanStopped
from auditor.reporting.html_report import render_report, write_report
from auditor.verification.integrity import audit_run
from auditor.planning.coverage import build_plan, reconcile_plan, build_coverage
from auditor.discovery.parser import extract_inventory
from auditor.discovery.crawler import crawl_inventory
from auditor.verification.deduplication import deduplicate_findings


def now():
    return datetime.now(timezone.utc).isoformat()


def save_json(path, value):
    import os
    import tempfile

    path = Path(path)
    content = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    temporary = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".pending-",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, path)

    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)



def save_evidence(run_dir, evidence):
    canonical = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    evidence["content_hash"] = {
        "algorithm": "sha256",
        "value": hashlib.sha256(canonical).hexdigest(),
        "scope": "Canonical JSON excluding content_hash",
    }

    save_json(
        run_dir / "evidence" / f"{evidence['id']}.json",
        evidence,
    )


async def _legacy_run_scan(target, profile, output, tool_version, reflection_param=None, exception_param=None):
    run_dir = Path(output) / f"scan-{uuid4().hex[:12]}"
    run_dir.mkdir(parents=True, exist_ok=False)

    for folder in ("results", "evidence", "reports", "discovery"):
        (run_dir / folder).mkdir()

    scan = {
        "id": run_dir.name,
        "target": target,
        "tool_version": tool_version,
        "profile": profile,
        "started_at": now(),
        "ended_at": None,
        "status": "running",
        "request_count": 0,
        "stop_reason": None,
        "supported_checks": ["CHK01", "CHK02", "CHK03", "CHK04", "CHK05", "CHK06", "CHK07", "CHK08"],
        "note": "Eight-check development assessment.",
    }
    save_json(run_dir / "scan.json", scan)

    plan = build_plan(target, reflection_param, exception_param)
    save_json(run_dir / "results" / "plan.json", plan)

    tests = []
    findings = []
    stop_reasons = []
    inventory = {
        "status": "not_parsed",
        "reason": "no_complete_response",
        "pages_parsed": 0,
        "additional_requests": 0,
        "records": [],
        "limits_reached": [],
    }

    def collect_header_results(response):
        new_tests, evidence, new_findings = review_headers(response)
        endpoint = response["final_url"]

        evidence["endpoint"] = endpoint
        save_evidence(run_dir, evidence)

        for new_test in new_tests:
            new_test["endpoint"] = endpoint

        for new_finding in new_findings:
            new_finding["affected_endpoints"] = [endpoint]

        tests.extend(new_tests)
        findings.extend(new_findings)

        cookie_test, cookie_evidence, cookie_findings = review_cookies(
            response
        )
        tests.append(cookie_test)
        save_evidence(run_dir, cookie_evidence)
        findings.extend(cookie_findings)

        error_test, error_evidence, error_findings = (
            review_error_disclosure(response)
        )
        tests.append(error_test)
        save_evidence(run_dir, error_evidence)
        findings.extend(error_findings)

        directory_test, directory_evidence, directory_findings = (
            review_directory_listing(response)
        )
        tests.append(directory_test)
        save_evidence(run_dir, directory_evidence)
        findings.extend(directory_findings)

    import asyncio

    client = None
    interruption_requested = False
    unexpected_error = None
    scan["operational_errors"] = []

    try:
        async with BoundedHTTPClient(target, profile) as client:
            scan["allowed_origins"] = [
                {"scheme": scheme, "host": host, "port": port}
                for scheme, host, port in sorted(client.allowed_origins)
            ]

            test, evidence, finding = await check_https_handling(
                target, profile, client=client
            )
            test["endpoint"] = target
            tests.append(test)

            if evidence:
                evidence["endpoint"] = target
                save_evidence(run_dir, evidence)

            if finding:
                finding["affected_endpoints"] = [target]
                findings.append(finding)

            if test.get("observed"):
                reason = test["observed"].get("stop_reason")
                if reason:
                    stop_reasons.append(reason)

            try:
                # A separate fetch for header review; all attempts share
                # the same scan budget and deadline.
                response = await client.fetch(target)
                inventory = extract_inventory(response, client.check_scope)

                collect_header_results(response)

            except ScanStopped as exc:
                stop_reasons.append(str(exc))
                new_tests = skipped_header_tests(
                    f"No complete response available: {exc}"
                )

                for new_test in new_tests:
                    new_test["endpoint"] = target

                tests.extend(new_tests)
                tests.append({
                    "id": f"test-{uuid4().hex[:12]}",
                    "rule_id": "CHK04",
                    "rule_version": "0.1.0",
                    "category": "A02:2025",
                    "title": "Cookie configuration observations",
                    "endpoint": target,
                    "status": "Not Tested",
                    "reason": f"No complete response available: {exc}",
                    "steps": [],
                    "expected": "A complete response for cookie inspection.",
                    "observed": None,
                    "request_count": 0,
                    "evidence_refs": [],
                    "limitations": ["Response retrieval did not complete."],
                })

            if not any(t["rule_id"] == "CHK05" for t in tests):
                tests.append({
                    "id": f"test-{uuid4().hex[:12]}",
                    "rule_id": "CHK05",
                    "rule_version": "0.1.0",
                    "category": "A02:2025",
                    "title": "Error disclosure indicators",
                    "endpoint": target,
                    "status": "Not Tested",
                    "reason": "No complete initial response available.",
                    "steps": [],
                    "expected": "A complete response for inspection.",
                    "observed": None,
                    "request_count": 0,
                    "evidence_refs": [],
                    "limitations": ["Initial retrieval did not complete."],
                })

            if not any(t["rule_id"] == "CHK06" for t in tests):
                tests.append({
                    "id": f"test-{uuid4().hex[:12]}",
                    "rule_id": "CHK06",
                    "rule_version": "0.1.0",
                    "category": "A02:2025",
                    "title": "Directory listing indicators",
                    "endpoint": target,
                    "status": "Not Tested",
                    "reason": "No complete initial response available.",
                    "steps": [],
                    "expected": "A complete directory response.",
                    "observed": None,
                    "request_count": 0,
                    "evidence_refs": [],
                    "limitations": ["Initial retrieval did not complete."],
                })

            inventory = await crawl_inventory(
                client,
                inventory,
                profile["max_depth"],
                on_response=collect_header_results,
            )

            if inventory["status"] == "partial":
                stop_reasons.append(
                    inventory.get("crawl_stop_reason")
                    or "discovery_partial"
                )

            if reflection_param:
                reflection_test, reflection_evidence, reflection_findings = (
                    await review_reflection(client, target, reflection_param)
                )
                tests.append(reflection_test)
                save_evidence(run_dir, reflection_evidence)
                findings.extend(reflection_findings)

                if reflection_test["status"] == "Inconclusive":
                    stop_reasons.append("reflection_inconclusive")
            else:
                tests.append(skipped_reflection(target))

            if exception_param:
                exceptional_test, exceptional_evidence, exceptional_findings = (
                    await review_exceptional(client, target, exception_param)
                )
                tests.append(exceptional_test)
                save_evidence(run_dir, exceptional_evidence)
                findings.extend(exceptional_findings)

                if exceptional_test["status"] == "Inconclusive":
                    stop_reasons.append("exceptional_input_inconclusive")
            else:
                tests.append(skipped_exceptional(target))

            scan["request_count"] = client.request_count
            save_json(run_dir / "request_ledger.json", client.ledger)


    except asyncio.CancelledError:
        interruption_requested = True
        stop_reasons.append("user_or_task_cancellation")

    except Exception as exc:
        unexpected_error = type(exc).__name__
        stop_reasons.append("unexpected_error")
        scan["operational_errors"].append({
            "type": unexpected_error,
            "message_retained": False,
        })

    finally:
        if client is not None:
            for record in client.ledger:
                if record.get("outcome") == "started":
                    record["outcome"] = (
                        "interrupted"
                        if interruption_requested
                        else "incomplete_after_error"
                    )

            scan["request_count"] = client.request_count
            save_json(run_dir / "request_ledger.json", client.ledger)
        else:
            save_json(run_dir / "request_ledger.json", [])

    if interruption_requested or unexpected_error:
        inventory["status"] = "partial"
        inventory["reason"] = (
            "user_or_task_cancellation"
            if interruption_requested else "unexpected_error"
        )

    save_json(
        run_dir / "discovery" / "endpoints.json",
        inventory,
    )
    scan["discovery"] = {
        "status": inventory["status"],
        "records": len(inventory["records"]),
        "pages_parsed": inventory["pages_parsed"],
        "limits_reached": inventory["limits_reached"],
    }
    scan["ended_at"] = now()
    scan["status"] = "partial" if stop_reasons else "finished"
    scan["stop_reason"] = (
        "; ".join(dict.fromkeys(stop_reasons))
        if stop_reasons else None
    )
    scan["rule_versions"] = {
        test["rule_id"]: test["rule_version"] for test in tests
    }

    save_json(run_dir / "scan.json", scan)
    save_json(run_dir / "results" / "tests.json", tests)
    save_json(
        run_dir / "results" / "plan.json",
        reconcile_plan(plan, tests),
    )
    save_json(
        run_dir / "results" / "coverage.json",
        build_coverage(tests),
    )
    raw_findings = findings
    findings = deduplicate_findings(raw_findings)

    save_json(
        run_dir / "results" / "findings_raw.json",
        raw_findings,
    )
    save_json(run_dir / "results" / "findings.json", findings)

    report = run_dir / "reports" / "report.html"
    write_report(run_dir)

    integrity_errors = audit_run(run_dir)
    integrity = {
        "status": "FAIL" if integrity_errors else "PASS",
        "checked_at": now(),
        "errors": integrity_errors,
        "scope": (
            "Saved test/evidence references, evidence hashes, "
            "request accounting and known fixture markers."
        ),
        "limitation": (
            "PASS does not mean the assessment completed, the target "
            "is secure, or all possible secrets were detected."
        ),
    }
    save_json(run_dir / "results" / "integrity.json", integrity)
    write_report(run_dir)
    print(f"Integrity audit: {integrity['status']}")

    for test in tests:
        print(f"{test['rule_id']}: {test['status']}")

    print(f"Requests attempted: {scan['request_count']}")
    print(f"Test records: {len(tests)}")
    print(f"Raw findings: {len(raw_findings)}")
    print(f"Grouped findings: {len(findings)}")
    print(f"Discovery records: {len(inventory['records'])}")
    print(f"Inventory: {(run_dir / 'discovery' / 'endpoints.json').resolve()}")
    print(f"Report: {report.resolve()}")

    if interruption_requested:
        raise asyncio.CancelledError()

    if unexpected_error:
        raise RuntimeError(
            "Scan stopped unexpectedly; inspect the saved partial run."
        )


async def run_scan(target, profile, output, tool_version, reflection_param=None,
                   exception_param=None, resume_dir=None, checks=None, crawl=None):
    from auditor.resume_engine import run_scan as checkpointed_scan
    return await checkpointed_scan(target, profile, output, tool_version,
        reflection_param=reflection_param, exception_param=exception_param,
        resume_dir=resume_dir, checks=checks, crawl=crawl)
