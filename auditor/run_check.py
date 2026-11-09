import argparse
import asyncio
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from auditor.__main__ import (
    TOOL_VERSION,
    load_profile,
    validate_url,
)
from auditor.checks.https_handling import (
    RULE_ID,
    RULE_VERSION,
    check_https_handling,
)


def write_json(path, value):
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


async def run(target, profile, run_dir, started_at):
    result, evidence, finding = await check_https_handling(
        target, profile
    )

    if evidence is not None:
        # Hash the evidence content before adding its hash field.
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

        write_json(
            run_dir / "evidence" / f"{evidence['id']}.json",
            evidence,
        )

    write_json(run_dir / "results" / "tests.json", [result])
    write_json(
        run_dir / "results" / "findings.json",
        [finding] if finding else [],
    )

    scan = {
        "id": run_dir.name,
        "tool_version": TOOL_VERSION,
        "rule_versions": {RULE_ID: RULE_VERSION},
        "profile": profile,
        "started_at": started_at,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "status": (
            "partial"
            if result["status"] == "Inconclusive"
            else "finished"
        ),
        "test_status": result["status"],
        "request_count": result["request_count"],
        "stop_reason": (
            result["observed"]["stop_reason"]
            if result["observed"]
            else None
        ),
        "note": "Single-rule development run, not a complete assessment.",
    }
    write_json(run_dir / "scan.json", scan)

    print(f"Rule     : {RULE_ID}")
    print(f"Status   : {result['status']}")
    print(f"Reason   : {result['reason']}")
    print(f"Requests : {result['request_count']}")
    print(f"Findings : {1 if finding else 0}")
    print(f"Output   : {run_dir.resolve()}")


def main():
    parser = argparse.ArgumentParser(
        description="Run CHK01 HTTPS handling."
    )
    parser.add_argument("--url", required=True)
    parser.add_argument(
        "--profile",
        type=Path,
        default=Path("config/public.json"),
    )
    args = parser.parse_args()

    try:
        target, _, _ = validate_url(args.url)
        profile = load_profile(args.profile)

        run_dir = Path("runs") / f"chk01-{uuid4().hex[:12]}"
        run_dir.mkdir(parents=True, exist_ok=False)
        (run_dir / "results").mkdir()
        (run_dir / "evidence").mkdir()

        started_at = datetime.now(timezone.utc).isoformat()
        asyncio.run(run(target, profile, run_dir, started_at))

    except (ValueError, OSError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
