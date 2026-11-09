import json
import unittest

import httpx

from auditor.checks.directory_listing import review_directory_listing
from auditor.discovery.parser import extract_inventory


def response(markup, path="/files/"):
    return {
        "final_url": "http://lab.example" + path,
        "status_code": 200,
        "headers": httpx.Headers({"Content-Type": "text/html"}),
        "body": markup.encode(),
    }


LISTING = """
<html>
<head><title>Directory listing for /files/</title></head>
<body>
<h1>Directory listing for /files/</h1>
<ul><li><a href="PRIVATE_FILE.html">PRIVATE_FILE.html</a></li></ul>
</body>
</html>
"""


class DirectoryListingTests(unittest.TestCase):
    def test_listing_is_potential_without_filename_retention(self):
        result = review_directory_listing(response(LISTING))
        test, evidence, findings = result

        self.assertEqual(test["status"], "Potential")
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            evidence["observation"]["local_child_links"], 1
        )
        self.assertNotIn("PRIVATE_FILE", json.dumps(result))

    def test_heading_alone_is_not_enough(self):
        test, _, findings = review_directory_listing(response(
            "<html><title>Index of /files/</title>"
            "<h1>Index of /files/</h1><p>Example text</p></html>"
        ))
        self.assertEqual(test["status"], "No Issue Observed")
        self.assertEqual(findings, [])

    def test_non_directory_url_is_skipped(self):
        test, _, _ = review_directory_listing(
            response(LISTING, path="/example.html")
        )
        self.assertEqual(test["status"], "Not Tested")

    def test_listing_entries_are_not_extracted(self):
        inventory = extract_inventory(
            response(LISTING), lambda url: url
        )
        self.assertEqual(inventory["records"], [])
        self.assertEqual(
            inventory["reason"],
            "recognized_listing_entries_not_expanded",
        )


if __name__ == "__main__":
    unittest.main()
