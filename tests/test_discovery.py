import json
import unittest

import httpx

from auditor.core.http_client import ScanStopped
from auditor.discovery.parser import extract_inventory


def scope(url):
    parsed = httpx.URL(url)
    if (
        parsed.scheme != "http"
        or parsed.host != "lab.example"
        or parsed.port not in {None, 80}
    ):
        raise ScanStopped("off_scope_url")
    return url


def response(markup, content_type="text/html"):
    return {
        "final_url": "http://lab.example/",
        "status_code": 200,
        "headers": httpx.Headers({"Content-Type": content_type}),
        "body": markup.encode(),
    }


class DiscoveryTests(unittest.TestCase):
    def test_query_and_form_values_are_omitted(self):
        inventory = extract_inventory(response("""
            <a href="/search?q=PRIVATE_QUERY">Search</a>
            <form action="/login" method="post">
              <input name="csrf" value="PRIVATE_TOKEN">
              <input name="password" type="password">
            </form>
        """), scope)

        encoded = json.dumps(inventory)
        self.assertNotIn("PRIVATE_QUERY", encoded)
        self.assertNotIn("PRIVATE_TOKEN", encoded)
        self.assertEqual(inventory["records"][0]["query_names"], ["q"])
        self.assertEqual(inventory["records"][1]["method"], "POST")
        self.assertEqual(inventory["additional_requests"], 0)

    def test_external_destination_is_blocked(self):
        inventory = extract_inventory(response(
            '<a href="https://outside.example/">Outside</a>'
        ), scope)

        self.assertEqual(
            inventory["records"][0]["scope_decision"], "blocked"
        )

    def test_base_href_is_respected(self):
        inventory = extract_inventory(response("""
            <base href="https://outside.example/folder/">
            <a href="page.html">Page</a>
        """), scope)

        record = inventory["records"][0]
        self.assertEqual(
            record["url"], "https://outside.example/folder/page.html"
        )
        self.assertEqual(record["scope_decision"], "blocked")

    def test_non_html_is_not_parsed(self):
        inventory = extract_inventory(
            response("{}", "application/json"), scope
        )
        self.assertEqual(inventory["status"], "not_parsed")
        self.assertEqual(inventory["records"], [])


if __name__ == "__main__":
    unittest.main()
