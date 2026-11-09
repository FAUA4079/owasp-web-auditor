import asyncio
import unittest

import httpx

from auditor.checks.https_handling import check_https_handling
from auditor.core.http_client import BoundedHTTPClient, ScanStopped


PROFILE = {
    "profile_name": "test",
    "max_requests": 5,
    "request_timeout_seconds": 2,
    "scan_deadline_seconds": 5,
    "max_response_bytes": 1024,
    "max_depth": 1,
    "max_redirects": 3,
    "verify_tls": True,
}


class Body(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b"Local test page"


def page():
    return httpx.Response(200, stream=Body())


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_response_is_potential(self):
        result, evidence, finding = await check_https_handling(
            "http://lab.example/",
            PROFILE,
            transport=httpx.MockTransport(lambda request: page()),
        )

        self.assertEqual(result["status"], "Potential")
        self.assertIsNotNone(finding)
        self.assertEqual(
            evidence["observation"]["final_scheme"], "http"
        )

    async def test_https_redirect(self):
        def handler(request):
            if request.url.scheme == "http":
                return httpx.Response(
                    301,
                    headers={"Location": "https://lab.example/"},
                )
            return page()

        result, evidence, finding = await check_https_handling(
            "http://lab.example/",
            PROFILE,
            transport=httpx.MockTransport(handler),
        )

        self.assertEqual(result["status"], "No Issue Observed")
        self.assertEqual(result["request_count"], 2)
        self.assertIsNone(finding)

    async def test_https_input_is_skipped(self):
        result, evidence, finding = await check_https_handling(
            "https://lab.example/", PROFILE
        )

        self.assertEqual(result["status"], "Not Tested")
        self.assertEqual(result["request_count"], 0)
        self.assertIsNone(evidence)

    async def test_shared_request_budget(self):
        profile = dict(PROFILE, max_requests=1)

        async with BoundedHTTPClient(
            "http://lab.example/",
            profile,
            transport=httpx.MockTransport(lambda request: page()),
        ) as client:
            await client.fetch("http://lab.example/")

            with self.assertRaisesRegex(
                ScanStopped, "request_budget_exhausted"
            ):
                await client.fetch("http://lab.example/")

            self.assertEqual(client.request_count, 1)

    async def test_overall_deadline(self):
        async def handler(request):
            await asyncio.sleep(2)
            return page()

        profile = dict(PROFILE, scan_deadline_seconds=1)

        async with BoundedHTTPClient(
            "http://lab.example/",
            profile,
            transport=httpx.MockTransport(handler),
        ) as client:
            with self.assertRaisesRegex(
                ScanStopped, "scan_deadline_reached"
            ):
                await client.fetch("http://lab.example/")

            self.assertEqual(
                client.ledger[0]["outcome"],
                "scan_deadline_reached",
            )


if __name__ == "__main__":
    unittest.main()
