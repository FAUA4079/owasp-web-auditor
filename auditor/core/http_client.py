import asyncio
from time import monotonic

import httpx

from auditor.__main__ import validate_url


class ScanStopped(Exception):
    """A request was stopped by policy or an operational limit."""


def origin(url):
    parsed = httpx.URL(url)
    default_port = 443 if parsed.scheme == "https" else 80
    return (
        parsed.scheme,
        parsed.host,
        parsed.port or default_port,
    )


class BoundedHTTPClient:
    def __init__(self, target, profile, transport=None):
        self.target, _, _ = validate_url(target)
        self.profile = profile
        self.transport = transport

        initial_origin = origin(self.target)
        self.allowed_origins = {initial_origin}

        scheme, host, port = initial_origin
        if scheme == "http" and port == 80:
            self.allowed_origins.add(("https", host, 443))

        self.request_count = 0
        self.ledger = []
        self.deadline = None
        self.client = None

    async def __aenter__(self):
        self.deadline = (
            monotonic() + self.profile["scan_deadline_seconds"]
        )
        self.client = httpx.AsyncClient(
            verify=True,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(
                self.profile["request_timeout_seconds"]
            ),
            limits=httpx.Limits(
                max_connections=1,
                max_keepalive_connections=1,
            ),
            headers={
                "User-Agent": "OWASP-Web-Auditor/0.1.0",
                "Accept-Encoding": "identity",
            },
            transport=self.transport,
        )
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        await self.client.aclose()

    def check_scope(self, url):
        try:
            normalized, _, _ = validate_url(url)
        except ValueError as exc:
            # Do not include a potentially sensitive URL in errors.
            raise ScanStopped("unsupported_url") from exc

        if origin(normalized) not in self.allowed_origins:
            raise ScanStopped("off_scope_url")

        return str(httpx.URL(normalized))

    async def _request_once(self, url, *, session_client=None, method="GET", json_body=None, headers=None):
        remaining = self.deadline - monotonic()

        if remaining <= 0:
            raise ScanStopped("scan_deadline_reached")

        if self.request_count >= self.profile["max_requests"]:
            raise ScanStopped("request_budget_exhausted")

        # Count attempts, including requests that fail to connect.
        self.request_count += 1

        record = {
            "request_number": self.request_count,
            "method": method,
            "status_code": None,
            "body_bytes_read": 0,
            "outcome": "started",
        }
        self.ledger.append(record)
        if getattr(self, "checkpoint_hook", None):
            self.checkpoint_hook()
        started = monotonic()

        try:
            # This outer timeout bounds the entire streamed operation.
            async with asyncio.timeout(remaining):
                client = self.client if session_client is None else session_client
                if session_client is None:
                    # Public scans remain stateless. Auth sessions use separate jars.
                    client.cookies.clear()

                async with client.stream(method, url, json=json_body, headers=headers) as response:
                    record["status_code"] = response.status_code

                    # Keep response headers in memory only for now.
                    headers = response.headers
                    location = headers.get("location")
                    body = bytearray()

                    if response.status_code in {
                        301, 302, 303, 307, 308
                    } and location is not None:
                        record["outcome"] = "redirect"
                        return {
                            "status_code": response.status_code,
                            "headers": headers,
                            "body": b"",
                            "location": location,
                        }

                    # Avoid decompression expansion at this stage.
                    encoding = headers.get(
                        "content-encoding", ""
                    ).strip().lower()

                    if encoding not in {"", "identity"}:
                        raise ScanStopped(
                            "encoded_response_not_supported"
                        )

                    size_cap = self.profile["max_response_bytes"]

                    async for chunk in response.aiter_raw(
                        chunk_size=8192
                    ):
                        available = size_cap - len(body)
                        body.extend(chunk[:available])
                        record["body_bytes_read"] = len(body)

                        if len(body) >= size_cap:
                            # Conservative: reaching the cap means
                            # completeness has not been established.
                            raise ScanStopped(
                                "response_size_cap_reached"
                            )

                    record["outcome"] = "received"
                    return {
                        "status_code": response.status_code,
                        "headers": headers,
                        "body": bytes(body),
                        "location": None,
                    }

        except ScanStopped as exc:
            record["outcome"] = str(exc)
            raise

        except TimeoutError as exc:
            record["outcome"] = "scan_deadline_reached"
            raise ScanStopped(record["outcome"]) from exc

        except httpx.TimeoutException as exc:
            record["outcome"] = "request_timeout"
            raise ScanStopped(record["outcome"]) from exc

        except httpx.HTTPError as exc:
            record["outcome"] = "network_error"
            record["error_type"] = type(exc).__name__
            raise ScanStopped(record["outcome"]) from exc

        finally:
            record["duration_seconds"] = round(
                monotonic() - started, 3
            )
            if getattr(self, "checkpoint_hook", None):
                self.checkpoint_hook()

    async def fetch_query_probe(self, url, parameter, value):
        # Validate the query-free destination before adding probe input.
        clean_url = self.check_scope(url)

        if not parameter or len(parameter) > 100:
            raise ValueError("Invalid probe parameter.")

        probe_url = httpx.URL(clean_url).copy_add_param(
            parameter, value
        )

        # Shared request ledger, deadline and response-size budget.
        result = await self._request_once(str(probe_url))

        # Never follow a query probe redirect in this rule version.
        result["final_url"] = clean_url
        return result

    async def fetch(self, url):
        current = url
        visited = set()
        redirects_followed = 0

        while True:
            current = self.check_scope(current)

            if current in visited:
                raise ScanStopped("redirect_loop")

            visited.add(current)
            result = await self._request_once(current)

            if result["location"] is None:
                result["final_url"] = current
                return result

            if redirects_followed >= self.profile["max_redirects"]:
                raise ScanStopped("redirect_limit_reached")

            try:
                next_url = str(
                    httpx.URL(current).join(result["location"])
                )
            except (httpx.InvalidURL, ValueError) as exc:
                raise ScanStopped("invalid_redirect") from exc

            if (
                origin(current)[0] == "https"
                and origin(next_url)[0] == "http"
            ):
                raise ScanStopped("https_downgrade_blocked")

            # Validate before any request to the redirect destination.
            current = self.check_scope(next_url)
            redirects_followed += 1

