import unittest

import httpx

from auditor.checks.headers import review_headers


def response(headers):
    return {
        "status_code": 200,
        "headers": httpx.Headers(headers),
    }


class HeaderTests(unittest.TestCase):
    def test_missing_headers_on_html(self):
        tests, evidence, findings = review_headers(
            response({"Content-Type": "text/html"})
        )
        self.assertEqual(
            [test["status"] for test in tests],
            ["Potential", "Potential"],
        )
        self.assertEqual(len(findings), 2)

    def test_configured_headers(self):
        tests, evidence, findings = review_headers(response({
            "Content-Type": "text/html",
            "Content-Security-Policy": "frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        }))
        self.assertEqual(tests[0]["status"], "Inconclusive")
        self.assertEqual(tests[1]["status"], "No Issue Observed")
        self.assertEqual(findings, [])

    def test_report_only_is_not_enforced_policy(self):
        tests, _, _ = review_headers(response({
            "Content-Type": "text/html",
            "Content-Security-Policy-Report-Only":
                "frame-ancestors 'none'",
        }))
        self.assertEqual(tests[0]["status"], "Potential")

    def test_non_html_framing_is_skipped(self):
        tests, _, _ = review_headers(response({
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff",
        }))
        self.assertEqual(tests[0]["status"], "Not Tested")
        self.assertEqual(tests[1]["status"], "No Issue Observed")


if __name__ == "__main__":
    unittest.main()
