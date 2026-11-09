import argparse
import hashlib
import json
from pathlib import Path


FIXTURE_SECRETS = (
    "PRIVATE_SECRET",
    "PRIVATE_PATH",
    "DO_NOT_SAVE_THIS",
    "VERY_PRIVATE_VALUE",
)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def audit_run(run_dir):
    run_dir = Path(run_dir)
    errors = []

    try:
        scan = load_json(run_dir / "scan.json")
        tests = load_json(run_dir / "results/tests.json")
        findings = load_json(run_dir / "results/findings.json")
        ledger = load_json(run_dir / "request_ledger.json")
    except (OSError, ValueError) as exc:
        return [f"Required output unreadable: {type(exc).__name__}"]

    if (
        not isinstance(scan, dict)
        or not isinstance(tests, list)
        or not isinstance(findings, list)
        or not isinstance(ledger, list)
    ):
        return ["Invalid top-level output structure."]

    def index_records(records, label):
        index = {}
        for record in records:
            if not isinstance(record, dict) or not record.get("id"):
                errors.append(f"{label}: invalid record or missing ID")
                continue
            identifier = record["id"]
            if not isinstance(identifier, str):
                errors.append(f"{label}: ID must be a string")
                continue
            if identifier in index:
                errors.append(f"{label}: duplicate ID {identifier}")
            index[identifier] = record
        return index

    test_index = index_records(tests, "Test")
    index_records(findings, "Finding")
    evidence_index = {}

    evidence_dir = run_dir / "evidence"
    if not evidence_dir.is_dir():
        errors.append("Evidence directory missing.")

    for path in evidence_dir.glob("*.json"):
        try:
            evidence = load_json(path)
            if not isinstance(evidence, dict):
                raise ValueError("Expected evidence object")

            identifier = evidence.get("id")
            if not isinstance(identifier, str) or identifier != path.stem:
                errors.append(f"Evidence ID/filename mismatch: {path.name}")
                continue

            evidence_index[identifier] = evidence
            hash_info = evidence.get("content_hash", {})
            payload = {
                key: value for key, value in evidence.items()
                if key != "content_hash"
            }
            canonical = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")

            expected = hashlib.sha256(canonical).hexdigest()

            if (
                hash_info.get("algorithm") != "sha256"
                or hash_info.get("scope")
                != "Canonical JSON excluding content_hash"
                or hash_info.get("value") != expected
            ):
                errors.append(f"Evidence hash mismatch: {identifier}")

        except (OSError, ValueError, AttributeError):
            errors.append(f"Unreadable evidence: {path.name}")

    for identifier, test in test_index.items():
        refs = test.get("evidence_refs", [])

        if test.get("status") != "Not Tested" and not refs:
            errors.append(f"Executed test lacks evidence: {identifier}")

        for evidence_id in refs:
            evidence = evidence_index.get(evidence_id)
            if evidence is None:
                errors.append(f"Missing evidence: {evidence_id}")
                continue

            owners = evidence.get("test_ids", [])
            if evidence.get("test_id"):
                owners = owners + [evidence["test_id"]]

            if identifier not in owners:
                errors.append(
                    f"Evidence backlink mismatch: {identifier} / {evidence_id}"
                )

    for identifier, evidence in evidence_index.items():
        owners = evidence.get("test_ids", [])
        if evidence.get("test_id"):
            owners = owners + [evidence["test_id"]]

        if not owners:
            errors.append(f"Evidence has no owning test: {identifier}")

        for owner in owners:
            if owner not in test_index:
                errors.append(f"Evidence references missing test: {owner}")
            elif identifier not in test_index[owner].get("evidence_refs", []):
                errors.append(f"Test lacks evidence backlink: {owner}")

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        contributing = finding.get("contributing_tests", [])
        refs = finding.get("evidence_refs", [])

        if not contributing or not refs:
            errors.append("Finding lacks test or evidence references.")

        allowed_evidence = set()
        for test_id in contributing:
            test = test_index.get(test_id)
            if test is None:
                errors.append(f"Finding references missing test: {test_id}")
            else:
                allowed_evidence.update(test.get("evidence_refs", []))

        for evidence_id in refs:
            if evidence_id not in evidence_index:
                errors.append(f"Finding references missing evidence: {evidence_id}")
            elif evidence_id not in allowed_evidence:
                errors.append(
                    f"Finding evidence not linked to contributing tests: {evidence_id}"
                )

    if scan.get("request_count") != len(ledger):
        errors.append("Scan request count does not match ledger length.")

    for number, record in enumerate(ledger, start=1):
        if not isinstance(record, dict) or record.get("request_number") != number:
            errors.append("Request ledger sequence is invalid.")
            break

    # Only checks known lab markers, not arbitrary production secrets.
    for folder in ("results", "evidence", "reports"):
        for path in (run_dir / folder).rglob("*"):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                errors.append(f"Unable to inspect output: {path.name}")
                continue
            if any(secret in text for secret in FIXTURE_SECRETS):
                errors.append(f"Known fixture marker retained: {path.name}")

    return errors


def main():
    parser = argparse.ArgumentParser(
        description="Audit saved run references, hashes and request accounting."
    )
    parser.add_argument("--run", required=True, type=Path)
    args = parser.parse_args()

    errors = audit_run(args.run)

    if errors:
        print("Integrity audit: FAIL")
        for error in errors:
            print("-", error)
        raise SystemExit(1)

    print("Integrity audit: PASS")
    print("Checked references, evidence hashes and request accounting.")
    print("Known fixture marker check passed; this is not a full secret scan.")


if __name__ == "__main__":
    main()
