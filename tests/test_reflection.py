import unittest
from urllib.parse import parse_qs

import httpx

from auditor.checks.reflection import review_reflection
from auditor.core.http_client import BoundedHTTPClient
from test_transport import PROFILE


class Body(httpx.AsyncByteStream):
    def __init__(self, value):
        self.value = value

    async def __aiter__(self):
        yield self.value


class ReflectionTests(unittest.IsolatedAsyncioTestCase):
    async def run_check(self, handler, profile=None):
        async with BoundedHTTPClient(
            "http://lab.example/search",
            profile or PROFILE,
            transport=httpx.MockTransport(handler),
        ) as client:
            return await review_reflection(
                client, "http://lab.example/search", "q"
            )

    async def test_marker_reflection_is_potential(self):
        def handler(request):
            query = parse_qs(request.url.query.decode())
            return httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                stream=Body(query["q"][0].encode()),
            )

        test, evidence, findings = await self.run_check(handler)
        self.assertEqual(test["status"], "Potential")
        self.assertEqual(test["request_count"], 2)
        self.assertEqual(test["observed"]["reflection_context"]["contexts"], ["plain_text"])
        self.assertEqual(evidence["observation"], test["observed"])
        self.assertEqual(len(findings), 1)

    async def test_no_reflection(self):
        def handler(request):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                stream=Body(b"Constant response"),
            )

        test, _, findings = await self.run_check(handler)
        self.assertEqual(test["status"], "No Issue Observed")
        self.assertEqual(findings, [])

    async def test_redirect_is_not_followed(self):
        requests = []

        def handler(request):
            requests.append(str(request.url))
            return httpx.Response(
                302,
                headers={"Location": "http://outside.example/"},
            )

        test, _, _ = await self.run_check(handler)
        self.assertEqual(test["status"], "Inconclusive")
        self.assertEqual(len(requests), 1)

    async def test_html_attribute_context_without_extra_requests_or_raw_retention(self):
        calls = []
        def handler(request):
            calls.append(request)
            value = parse_qs(request.url.query.decode())["q"][0]
            return httpx.Response(200, headers={"Content-Type": "text/html"},
                                 stream=Body(('<input value="' + value + '">SECRET_BODY').encode()))
        test, evidence, findings = await self.run_check(handler)
        self.assertEqual(len(calls), 2)
        self.assertEqual(test['status'], 'Potential')
        self.assertEqual(test['observed']['reflection_context']['contexts'], ['html_attribute'])
        self.assertNotIn('SECRET_BODY', str(evidence))
        self.assertNotIn('AUDITOR_', str(evidence))
