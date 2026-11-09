import json
import unittest

import httpx

from auditor.checks.cookies import review_cookies


def response(cookies):
    return {
        "final_url": "https://lab.example/",
        "status_code": 200,
        "headers": httpx.Headers([
            ("Set-Cookie", value) for value in cookies
        ]),
    }


class CookieTests(unittest.TestCase):
    def test_absent_cookie_is_not_tested(self):
        test, evidence, findings = review_cookies(response([]))
        self.assertEqual(test["status"], "Not Tested")
        self.assertEqual(findings, [])

    def test_missing_attributes_and_no_value_retention(self):
        test, evidence, findings = review_cookies(response([
            "session=VERY_PRIVATE_VALUE; Path=/",
        ]))

        self.assertEqual(test["status"], "Potential")
        self.assertEqual(len(findings), 1)
        self.assertNotIn(
            "VERY_PRIVATE_VALUE",
            json.dumps([test, evidence, findings]),
        )

    def test_configured_cookie(self):
        test, evidence, findings = review_cookies(response([
            "session=SECRET; Secure; HttpOnly; SameSite=Lax; Path=/",
        ]))

        self.assertEqual(test["status"], "No Issue Observed")
        self.assertEqual(findings, [])

    def test_multiple_cookie_headers_and_samesite_none(self):
        test, evidence, findings = review_cookies(response([
            "a=ONE; Secure; HttpOnly; SameSite=Strict",
            "b=TWO; HttpOnly; SameSite=None",
        ]))

        observed = evidence["observation"]
        self.assertEqual(observed["parsed_cookie_count"], 2)
        self.assertIn(
            "samesite_none_without_secure",
            observed["cookies"][1]["concerns"],
        )


if __name__ == "__main__":
    unittest.main()
