import json
import tempfile
import unittest
from pathlib import Path

from auditor.reporting.html_report import render_report


class ReportTests(unittest.TestCase):
    def test_target_markup_is_escaped(self):
        marker = '<script>alert("test")</script>'

        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "results").mkdir()
            (run_dir / "evidence").mkdir()

            (run_dir / "scan.json").write_text(
                json.dumps({"id": "test-run", "tool_version": "test", "status": "finished", "request_count": 0, "started_at": "2026-10-20T00:00:00+00:00", "ended_at": None}),
                encoding="utf-8",
            )

            (run_dir / "results" / "tests.json").write_text(
                json.dumps([{
                    "rule_id": "CHK01", "id": "test-escape", "rule_version": "1.0",
                    "category": "A04:2025", "status": "Not Tested",
                    "steps": [], "expected": "test", "limitations": [],
                    "evidence_refs": [], "request_count": 0,
                    "title": "Escaping test",
                    "reason": marker,
                }]),
                encoding="utf-8",
            )

            (run_dir / "results" / "findings.json").write_text(
                "[]",
                encoding="utf-8",
            )

            document = render_report(run_dir)

            self.assertNotIn(marker, document)
            self.assertIn(
                "&lt;script&gt;alert(&quot;test&quot;)&lt;/script&gt;",
                document,
            )
            self.assertIn("Content-Security-Policy", document)


if __name__ == "__main__":
    unittest.main()
