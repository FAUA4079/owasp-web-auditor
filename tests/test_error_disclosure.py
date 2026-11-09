import json
import unittest

import httpx

from auditor.checks.error_disclosure import review_error_disclosure


def response(body, status=200, media_type="text/plain"):
    return {
        "final_url": "http://lab.example/error.html",
        "status_code": status,
        "headers": httpx.Headers({"Content-Type": media_type}),
        "body": body.encode(),
    }


class ErrorDisclosureTests(unittest.TestCase):
    def test_traceback_is_potential_and_secrets_are_omitted(self):
        result = review_error_disclosure(response(
            'Traceback (most recent call last):\n'
            '  File "/srv/PRIVATE_PATH/app.py", line 42, in view\n'
            'RuntimeError: password=PRIVATE_SECRET\n'
        ))

        test, evidence, findings = result
        self.assertEqual(test["status"], "Potential")
        self.assertEqual(len(findings), 1)

        serialized = json.dumps(result)
        self.assertNotIn("PRIVATE_PATH", serialized)
        self.assertNotIn("PRIVATE_SECRET", serialized)
        self.assertIn("[REDACTED_PATH]", serialized)

    def test_500_without_error_structure_is_not_a_finding(self):
        test, _, findings = review_error_disclosure(
            response("Service unavailable", status=500)
        )
        self.assertEqual(test["status"], "No Issue Observed")
        self.assertEqual(findings, [])

    def test_php_error_structure(self):
        test, evidence, _ = review_error_disclosure(response(
            "Fatal error: PRIVATE_MESSAGE in /srv/app/index.php on line 12"
        ))
        self.assertEqual(test["status"], "Potential")
        self.assertNotIn("PRIVATE_MESSAGE", json.dumps(evidence))

    def test_documentation_example_is_not_confirmed(self):
        test, _, _ = review_error_disclosure(response(
            '<html><body><h1>Traceback tutorial</h1><pre>'
            'Traceback (most recent call last):\n'
            'File "/example/demo.py", line 9\n'
            '</pre></body></html>',
            media_type="text/html",
        ))
        self.assertEqual(test["status"], "Potential")


if __name__ == "__main__":
    unittest.main()
