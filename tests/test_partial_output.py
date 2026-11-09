import asyncio
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from auditor.scanner import run_scan
from test_transport import PROFILE


class PartialOutputTests(unittest.IsolatedAsyncioTestCase):
    async def execute_failure(self, error):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name)

        with patch(
            "auditor.core.http_client.BoundedHTTPClient.fetch",
            side_effect=error,
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(type(error)):
                    await run_scan(
                        "https://lab.example/",
                        PROFILE,
                        output,
                        "test-version",
                    )

        runs = list(output.glob("scan-*"))
        self.assertEqual(len(runs), 1)
        return runs[0]

    async def test_unexpected_error_preserves_partial_outputs(self):
        run = await self.execute_failure(
            RuntimeError("SENSITIVE_ERROR_MESSAGE")
        )
        scan = json.loads((run / "scan.json").read_text())
        self.assertEqual(scan["status"], "partial")
        self.assertIn("unexpected_error", scan["stop_reason"])

        for name in (
            "tests.json",
            "findings.json",
            "coverage.json",
            "plan.json",
            "integrity.json",
        ):
            self.assertTrue((run / "results" / name).exists())

        self.assertTrue((run / "reports/report.html").exists())

        for path in run.rglob("*"):
            if path.is_file():
                self.assertNotIn(
                    "SENSITIVE_ERROR_MESSAGE",
                    path.read_text(encoding="utf-8"),
                )

    async def test_cancellation_preserves_partial_outputs(self):
        run = await self.execute_failure(asyncio.CancelledError())
        scan = json.loads((run / "scan.json").read_text())

        self.assertEqual(scan["status"], "partial")
        self.assertIn("user_or_task_cancellation", scan["stop_reason"])

        plan = json.loads((run / "results/plan.json").read_text())
        self.assertTrue(any(
            check["record_state"] == "missing_result"
            for check in plan["checks"]
        ))

        integrity = json.loads(
            (run / "results/integrity.json").read_text()
        )
        self.assertEqual(integrity["status"], "PASS")
