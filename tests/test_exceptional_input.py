import unittest
from urllib.parse import parse_qs

import httpx

from auditor.checks.exceptional_input import review_exceptional
from auditor.core.http_client import BoundedHTTPClient
from test_transport import PROFILE


class Body(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b"Generic response"


class ExceptionalInputTests(unittest.IsolatedAsyncioTestCase):
    async def run_check(self, malformed_status, budget=5):
        def handler(request):
            value = parse_qs(request.url.query.decode())["id"][0]
            status = 200 if value == "1" else malformed_status

            return httpx.Response(
                status,
                headers={"Content-Type": "text/plain"},
                stream=Body(),
            )

        profile = dict(PROFILE, max_requests=budget)

        async with BoundedHTTPClient(
            "http://lab.example/item",
            profile,
            transport=httpx.MockTransport(handler),
        ) as client:
            return await review_exceptional(
                client, "http://lab.example/item", "id"
            )

    async def test_server_error_is_potential_not_confirmed(self):
        test, _, findings = await self.run_check(500)
        self.assertEqual(test["status"], "Potential")
        self.assertEqual(test["request_count"], 2)
        self.assertEqual(len(findings), 1)

    async def test_client_rejection_has_no_observed_issue(self):
        test, _, findings = await self.run_check(400)
        self.assertEqual(test["status"], "No Issue Observed")
        self.assertEqual(findings, [])

    async def test_accepting_input_is_inconclusive(self):
        test, _, _ = await self.run_check(200)
        self.assertEqual(test["status"], "Inconclusive")

    async def test_shared_budget_stops_probe(self):
        test, evidence, _ = await self.run_check(500, budget=1)
        self.assertEqual(test["status"], "Inconclusive")
        self.assertEqual(test["request_count"], 1)
        self.assertEqual(
            evidence["observation"]["stop_reason"],
            "request_budget_exhausted",
        )


if __name__ == "__main__":
    unittest.main()
