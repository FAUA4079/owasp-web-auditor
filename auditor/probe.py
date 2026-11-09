import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from auditor.__main__ import load_profile, validate_url
from auditor.core.http_client import (
    BoundedHTTPClient,
    ScanStopped,
)


async def run_probe(target, profile, run_dir):
    summary = {
        "stage": "http_client_probe",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "stop_reason": None,
        "request_count": 0,
        "response_status": None,
        "body_bytes_read": 0,
        "checks_executed": 0,
    }

    async with BoundedHTTPClient(target, profile) as client:
        try:
            response = await client.fetch(target)
            summary["status"] = "retrieval_completed"
            summary["response_status"] = response["status_code"]
            summary["body_bytes_read"] = len(response["body"])

        except ScanStopped as exc:
            summary["status"] = "stopped"
            summary["stop_reason"] = str(exc)

        finally:
            summary["request_count"] = client.request_count
            summary["ended_at"] = (
                datetime.now(timezone.utc).isoformat()
            )

            (run_dir / "probe.json").write_text(
                json.dumps(summary, indent=2) + "\n",
                encoding="utf-8",
            )
            (run_dir / "request_ledger.json").write_text(
                json.dumps(client.ledger, indent=2) + "\n",
                encoding="utf-8",
            )

    print(json.dumps(summary, indent=2))
    print(f"\nOutput directory: {run_dir.resolve()}")


def main():
    parser = argparse.ArgumentParser(
        description="Test bounded HTTP retrieval."
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

        run_dir = Path("runs") / f"probe-{uuid4().hex[:12]}"
        run_dir.mkdir(parents=True, exist_ok=False)

    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    try:
        asyncio.run(run_probe(target, profile, run_dir))
    except OSError as exc:
        parser.exit(1, f"Could not save probe output: {exc}\n")


if __name__ == "__main__":
    main()
