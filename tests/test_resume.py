import asyncio
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
from auditor.resume_engine import run_scan, read_checkpoint, lock_run
from auditor.verification.integrity import audit_run

PROFILE = {
    'profile_name': 'resume-test', 'max_requests': 30,
    'request_timeout_seconds': 2, 'scan_deadline_seconds': 60,
    'max_response_bytes': 4096, 'max_depth': 2,
    'max_redirects': 3, 'verify_tls': True,
}
REAL_CLIENT = httpx.AsyncClient


class Body(httpx.AsyncByteStream):
    def __init__(self, data):
        self.data = data
    async def __aiter__(self):
        yield self.data


def reply(data, content_type='text/html'):
    return httpx.Response(200, headers={'Content-Type': content_type}, stream=Body(data))


class ResumeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)

    def transport(self, handler):
        def factory(*args, **kwargs):
            kwargs['transport'] = httpx.MockTransport(handler)
            return REAL_CLIENT(*args, **kwargs)
        return patch('auditor.core.http_client.httpx.AsyncClient', side_effect=factory)

    async def scan(self, handler, resume=None, reflection=None, profile=None):
        with self.transport(handler), contextlib.redirect_stdout(io.StringIO()):
            await run_scan('http://lab.example/start.html', profile or PROFILE,
                           self.output, 'test-version', reflection_param=reflection,
                           resume_dir=resume)

    def latest(self):
        return next(self.output.glob('scan-*'))

    async def test_resume_skips_completed_pages_and_preserves_ledger(self):
        requests = []
        def first(request):
            path = request.url.path
            requests.append(path)
            if path == '/start.html':
                return reply(b'<a href="/a.html">A</a><a href="/b.html">B</a>')
            if path == '/a.html':
                return reply(b'<p>A</p>')
            raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            await self.scan(first)
        run = self.latest()
        before = read_checkpoint(run)
        completed_ids = [t['id'] for t in before['tests']]
        self.assertEqual(before['request_count'], 3)
        self.assertEqual(before['queue'][0]['url'], 'http://lab.example/b.html')
        def second(request):
            requests.append(request.url.path)
            return reply(b'<p>B</p>')
        await self.scan(second, resume=run)
        after = read_checkpoint(run)
        self.assertEqual(requests, ['/start.html', '/a.html', '/b.html', '/b.html'])
        self.assertEqual(after['request_count'], 4)
        self.assertTrue(after['complete'])
        self.assertTrue(set(completed_ids).issubset({t['id'] for t in after['tests']}))
        self.assertEqual(len(after['ledger']), 4)
        self.assertEqual(audit_run(run), [])

    async def test_probe_pair_restarts_without_duplicate_completed_tests(self):
        first_requests = []
        def first(request):
            first_requests.append(str(request.url))
            if len(first_requests) == 3:
                raise asyncio.CancelledError()
            return reply(b'baseline', 'text/plain')
        with self.assertRaises(asyncio.CancelledError):
            await self.scan(first, reflection='q')
        run = self.latest()
        resumed_queries = []
        def second(request):
            value = request.url.params.get('q', '')
            resumed_queries.append(value)
            return reply(value.encode(), 'text/plain')
        await self.scan(second, resume=run)
        state = read_checkpoint(run)
        self.assertEqual(len(resumed_queries), 2)
        self.assertEqual(resumed_queries[0], 'auditor_baseline')
        self.assertTrue(resumed_queries[1].startswith('AUDITOR_'))
        self.assertEqual(state['request_count'], 5)
        self.assertEqual(len([t for t in state['tests'] if t['rule_id'] == 'CHK07']), 1)
        self.assertEqual(audit_run(run), [])

    async def test_completed_resume_sends_no_requests(self):
        await self.scan(lambda request: reply(b'<p>done</p>'))
        run = self.latest()
        def forbidden(request):
            self.fail('Completed run sent a request')
        await self.scan(forbidden, resume=run)

    async def test_active_time_is_carried_forward_not_pause_time(self):
        def stop(request):
            raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            await self.scan(stop)
        run = self.latest()
        before = read_checkpoint(run)['active_seconds']
        await asyncio.sleep(1.0)
        await self.scan(lambda request: reply(b'<p>done</p>'), resume=run)
        after = read_checkpoint(run)['active_seconds']
        self.assertGreaterEqual(after, before)
        self.assertLess(after - before, 1.0)

    async def test_exhausted_request_budget_cannot_reset_on_resume(self):
        def stop(request):
            raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            await self.scan(stop, profile=dict(PROFILE, max_requests=1))
        with self.assertRaisesRegex(ValueError, 'budget exhausted'):
            await self.scan(lambda r: self.fail('No request permitted'), resume=self.latest())

    async def test_changed_code_fingerprint_is_rejected(self):
        def stop(request):
            raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            await self.scan(stop)
        with patch('auditor.resume_engine.fingerprint', return_value='changed'):
            with self.assertRaisesRegex(ValueError, 'version differs'):
                await self.scan(lambda r: self.fail('No request permitted'), resume=self.latest())

    async def test_second_process_lock_is_rejected(self):
        run = self.output / 'locked'
        run.mkdir()
        with lock_run(run):
            with self.assertRaisesRegex(ValueError, 'already active'):
                with lock_run(run):
                    pass

    async def test_legacy_run_has_no_resume_checkpoint(self):
        run = self.output / 'legacy'
        run.mkdir()
        with self.assertRaisesRegex(ValueError, 'No resume checkpoint'):
            await self.scan(lambda r: self.fail('No request permitted'), resume=run)
