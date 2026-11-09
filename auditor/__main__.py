import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4


TOOL_VERSION = "0.2.0rc1"


def validate_url(value):
    """Validate and normalize the target without sending a request."""
    value = value.strip()

    if any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError("URL must not contain whitespace or control characters.")

    if "\\" in value:
        raise ValueError("URL must not contain backslashes.")

    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc

    if parts.scheme not in {"http", "https"}:
        raise ValueError("URL must begin with http:// or https://")

    if not host:
        raise ValueError("URL must contain a hostname or IP address.")

    if parts.username is not None or parts.password is not None:
        raise ValueError("Credentials in URLs are not supported.")

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    # Avoid persisting query secrets before the redaction module exists.
    if parts.query:
        raise ValueError(
            "This setup version accepts URLs without query parameters."
        )

    normalized = urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path or "/",
            "",
            "",  # Fragments are not sent in HTTP requests.
        )
    )

    return normalized, host.lower(), port


def load_profile(path):
    """Read the profile and reject missing or invalid settings."""
    with path.open(encoding="utf-8") as handle:
        profile = json.load(handle)

    if not isinstance(profile, dict):
        raise ValueError("Profile must be a JSON object.")

    name = profile.get("profile_name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("profile_name must be a non-empty string.")

    positive_fields = (
        "max_requests",
        "request_timeout_seconds",
        "scan_deadline_seconds",
        "max_response_bytes",
    )

    for key in positive_fields:
        value = profile.get(key)
        if type(value) is not int or value <= 0:
            raise ValueError(f"{key} must be a positive integer.")

    for key in ("max_depth", "max_redirects"):
        value = profile.get(key)
        if type(value) is not int or value < 0:
            raise ValueError(f"{key} must be a non-negative integer.")

    if profile.get("verify_tls") is not True:
        raise ValueError("This version requires verify_tls to be true.")

    return profile


def default_profile_path():
    local = Path("config/public.json")
    return local if local.is_file() else Path(__file__).parent / "data/public.json"


def main():
    import asyncio
    from auditor.reporting.ai import run_scan_with_ai as run_scan

    parser = argparse.ArgumentParser(
        prog="auditor",
        description="OWASP Web Auditor — development scanner."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {TOOL_VERSION}",
    )
    parser.add_argument("--url")
    parser.add_argument("--project", help="Project JSON for account preflight (use with --check-accounts or --validate-project)")
    parser.add_argument("--prompt-credentials", action="store_true", help="Prompt for project account credentials")
    parser.add_argument("--assess", action="store_true", help="Run the configured AuditShop authenticated assessment")
    parser.add_argument("--check-accounts", action="store_true", help="Verify configured accounts with isolated sessions; no vulnerability scan")
    parser.add_argument("--validate-project", action="store_true", help="Validate project configuration offline")
    parser.add_argument("--list-checks", action="store_true", help="List checks without network requests")
    parser.add_argument("--checks", help="Comma-separated IDs, e.g. CHK02,CHK03; default: all")
    parser.add_argument("--no-crawl", action="store_true", help="Inspect only the supplied page; do not follow discovered links")
    parser.add_argument(
        "--profile",
        type=Path,
        default=default_profile_path(),
        help="Profile JSON (local config/public.json, otherwise bundled public profile)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("runs"),
    )
    parser.add_argument(
        "--reflection-param",
        help="Explicitly selected read-only query parameter to test",
    )
    parser.add_argument(
        "--exception-param",
        help="Explicitly selected numeric read-only query parameter",
    )
    parser.add_argument("--resume", metavar="RUN_DIR", help="Resume a checkpointed run using its saved settings")
    from auditor.reporting.ai import add_ai_arguments, apply_ai_arguments
    add_ai_arguments(parser)
    args = parser.parse_args()
    apply_ai_arguments(args)
    from auditor.planning.selection import select_checks, print_checks
    if args.list_checks:
        print_checks()
        return
    if not args.url:
        parser.error('--url is required unless --list-checks is used.')
    try:
        select_checks(args.checks, args.reflection_param, args.exception_param)
    except ValueError as exc:
        parser.error(str(exc))

    if args.exception_param is not None:
        if (
            not args.exception_param.strip()
            or len(args.exception_param) > 100
            or any(ord(char) < 32 for char in args.exception_param)
        ):
            parser.error("Invalid exceptional-input parameter.")


    if args.reflection_param is not None:
        if (
            not args.reflection_param.strip()
            or len(args.reflection_param) > 100
            or any(ord(char) < 32 for char in args.reflection_param)
        ):
            parser.error("Invalid reflection parameter.")


    try:
        target, _, _ = validate_url(args.url)
        profile = load_profile(args.profile)

        asyncio.run(
            run_scan(
                target,
                profile,
                args.output,
                TOOL_VERSION,
                reflection_param=args.reflection_param,
                exception_param=args.exception_param,
                checks=args.checks,
                crawl=not args.no_crawl,
            )
        )
    except KeyboardInterrupt:
        parser.exit(
            130,
            "Interrupted. Check the latest run for saved partial outputs.\n"
        )
    except (ValueError, OSError, RuntimeError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    from auditor.cli import main as entry_point
    entry_point()
