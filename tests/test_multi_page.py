import unittest
from copy import deepcopy

import httpx

from auditor.discovery.crawler import crawl_inventory
from auditor.discovery.parser import extract_inventory
from auditor.verification.deduplication import deduplicate_findings


class DeduplicationTests(unittest.TestCase):
    def finding(self, identifier, endpoint):
        return {
            "id": identifier,
            "rule_id": "CHK03",
            "category": "A02:2025",
            "title": "Content type protection",
            "status": "Potential",
            "severity": "Informational",
            "confidence": "Configuration observation only",
            "impact": "nosniff missing",
            "fix": "Configure nosniff",
            "retest": "Fetch again",
            "affected_endpoints": [endpoint],
            "contributing_tests": [f"test-{identifier}"],
            "evidence_refs": [f"ev-{identifier}"],
        }

    def test_matching_findings_preserve_all_references(self):
        findings = [
            self.finding("one", "http://lab.example/a.html"),
            self.finding("two", "http://lab.example/b.html"),
        ]
        original = deepcopy(findings)

        grouped = deduplicate_findings(findings)

        self.assertEqual(len(grouped), 1)
        self.assertEqual(len(grouped[0]["affected_endpoints"]), 2)
        self.assertEqual(len(grouped[0]["contributing_tests"]), 2)
        self.assertEqual(len(grouped[0]["evidence_refs"]), 2)
        self.assertEqual(findings, original)

    def test_different_impact_is_not_merged(self):
        first = self.finding("one", "http://lab.example/a.html")
        second = self.finding("two", "http://lab.example/b.html")
        second["impact"] = "Content-Type missing"

        self.assertEqual(
            len(deduplicate_findings([first, second])), 2
        )


class CallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_callback_uses_fetched_response_without_refetch(self):
        class Client:
            request_count = 0

            def check_scope(self, url):
                return url

            async def fetch(self, url):
                self.request_count += 1
                return {
                    "final_url": url,
                    "status_code": 200,
                    "headers": httpx.Headers({
                        "Content-Type": "text/html"
                    }),
                    "body": b"<p>Child page</p>",
                }

        client = Client()
        seed = extract_inventory({
            "final_url": "http://lab.example/start.html",
            "status_code": 200,
            "headers": httpx.Headers({"Content-Type": "text/html"}),
            "body": b'<a href="/child.html">Child</a>',
        }, client.check_scope)

        observed = []

        await crawl_inventory(
            client,
            seed,
            max_depth=1,
            on_response=lambda response: observed.append(
                response["final_url"]
            ),
        )

        self.assertEqual(client.request_count, 1)
        self.assertEqual(
            observed, ["http://lab.example/child.html"]
        )


if __name__ == "__main__":
    unittest.main()
