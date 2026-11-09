import unittest

import httpx

from auditor.core.http_client import ScanStopped
from auditor.discovery.crawler import crawl_inventory
from auditor.discovery.parser import extract_inventory


def response(url, markup):
    return {
        "final_url": url,
        "status_code": 200,
        "headers": httpx.Headers({"Content-Type": "text/html"}),
        "body": markup.encode(),
    }


class FakeClient:
    def __init__(self, pages, budget=10):
        self.pages = pages
        self.budget = budget
        self.request_count = 0
        self.requested = []

    def check_scope(self, url):
        parsed = httpx.URL(url)
        if (
            parsed.scheme != "http"
            or parsed.host != "lab.example"
            or parsed.port not in {None, 80}
        ):
            raise ScanStopped("off_scope_url")
        return url

    async def fetch(self, url):
        self.check_scope(url)

        if self.request_count >= self.budget:
            raise ScanStopped("request_budget_exhausted")

        self.request_count += 1
        self.requested.append(url)
        return response(url, self.pages[url])


class CrawlerTests(unittest.IsolatedAsyncioTestCase):
    async def test_depth_and_duplicates(self):
        client = FakeClient({
            "http://lab.example/a.html": (
                '<a href="/b.html">B</a>'
                '<a href="/start.html">Back</a>'
            ),
        })

        seed = extract_inventory(response(
            "http://lab.example/start.html",
            '<a href="/a.html">A</a><a href="/a.html">Again</a>',
        ), client.check_scope)

        result = await crawl_inventory(client, seed, max_depth=1)

        self.assertEqual(
            client.requested, ["http://lab.example/a.html"]
        )
        self.assertIn("depth_limit", result["limits_reached"])
        self.assertEqual(result["pages_parsed"], 2)

    async def test_query_form_and_external_are_not_fetched(self):
        client = FakeClient({})

        seed = extract_inventory(response(
            "http://lab.example/start.html",
            """
            <a href="/a.html?token=SECRET">Query</a>
            <a href="http://outside.example/a.html">Outside</a>
            <form action="/submit.html" method="post"></form>
            """,
        ), client.check_scope)

        result = await crawl_inventory(client, seed, max_depth=2)

        self.assertEqual(client.requested, [])
        self.assertEqual(result["additional_requests"], 0)
        self.assertEqual(len(result["records"]), 3)

    async def test_budget_stop_preserves_inventory(self):
        client = FakeClient({
            "http://lab.example/a.html": "<p>A</p>",
        }, budget=1)

        seed = extract_inventory(response(
            "http://lab.example/start.html",
            '<a href="/a.html">A</a><a href="/b.html">B</a>',
        ), client.check_scope)

        result = await crawl_inventory(client, seed, max_depth=2)

        self.assertEqual(result["status"], "partial")
        self.assertEqual(
            result["crawl_stop_reason"], "request_budget_exhausted"
        )
        self.assertEqual(client.request_count, 1)
        self.assertEqual(len(result["records"]), 2)


if __name__ == "__main__":
    unittest.main()
