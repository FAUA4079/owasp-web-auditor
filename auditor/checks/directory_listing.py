from datetime import datetime, timezone
from urllib.parse import unquote, urljoin, urlsplit
from uuid import uuid4

from bs4 import BeautifulSoup


def review_directory_listing(response):
    endpoint = response["final_url"]
    parts = urlsplit(endpoint)

    media_type = response["headers"].get(
        "content-type", ""
    ).split(";", 1)[0].strip().lower()

    supported = (
        parts.path.endswith("/")
        and media_type == "text/html"
        and 200 <= response["status_code"] < 300
    )

    observation = {
        "http_status": response["status_code"],
        "directory_url": parts.path.endswith("/"),
        "matching_title_and_heading": False,
        "listing_container_present": False,
        "local_child_links": 0,
    }

    if supported:
        soup = BeautifulSoup(response["body"], "html.parser")
        title = soup.find("title")
        heading = soup.find("h1")

        title_text = (
            title.get_text(" ", strip=True) if title else ""
        )
        heading_text = (
            heading.get_text(" ", strip=True) if heading else ""
        )

        # Recognize common autoindex headings for this exact path.
        paths = {parts.path, unquote(parts.path)}
        expected = {
            f"{prefix}{path}".casefold()
            for prefix in ("Directory listing for ", "Index of ")
            for path in paths
        }

        observation["matching_title_and_heading"] = (
            title_text.casefold() in expected
            and heading_text.casefold() in expected
        )

        containers = soup.find_all(["ul", "table", "pre"])
        observation["listing_container_present"] = bool(containers)

        child_urls = set()

        for container in containers:
            for link in container.find_all("a", href=True):
                try:
                    child = urlsplit(urljoin(endpoint, link["href"]))
                    if (
                        child.scheme == parts.scheme
                        and child.netloc == parts.netloc
                        and not child.query
                        and child.path.startswith(parts.path)
                        and child.path != parts.path
                    ):
                        child_urls.add(child.path)
                except ValueError:
                    continue

        observation["local_child_links"] = len(child_urls)

    detected = (
        observation["matching_title_and_heading"]
        and observation["listing_container_present"]
        and observation["local_child_links"] > 0
    )

    if not supported:
        status = "Not Tested"
        reason = (
            "Requires a successful text/html response at a URL "
            "whose path ends with '/'."
        )
    elif detected:
        status = "Potential"
        reason = (
            "A common directory-listing structure with local child "
            "links was observed. Whether publication is unintended "
            "or exposes sensitive files has not been established."
        )
    else:
        status = "No Issue Observed"
        reason = (
            "No supported directory-listing structure was observed. "
            "Custom or empty listings may not be recognized."
        )

    test_id = f"test-{uuid4().hex[:12]}"
    evidence_id = f"ev-{uuid4().hex[:12]}"

    test = {
        "id": test_id,
        "rule_id": "CHK06",
        "rule_version": "0.1.0",
        "category": "A02:2025",
        "title": "Directory listing indicators",
        "endpoint": endpoint,
        "status": status,
        "reason": reason,
        "steps": (
            ["Compare directory title, heading and local entry-link structure."]
            if supported else []
        ),
        "expected": "Directory contents are exposed only when intended.",
        "observed": observation,
        "request_count": 0,
        "evidence_refs": [evidence_id],
        "limitations": [
            "Only common English autoindex structures are recognized.",
            "Custom and empty listings may be missed.",
            "Listed files are not requested by this check.",
            "File names, link targets and file contents are not retained.",
            "Publication intent and sensitive content are not assessed.",
        ],
    }

    evidence = {
        "id": evidence_id,
        "test_id": test_id,
        "endpoint": endpoint,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "kind": "directory_listing_structure",
        "observation": observation,
        "raw_body_retained": False,
        "listed_filenames_retained": False,
    }

    findings = []

    if detected:
        findings.append({
            "id": f"finding-{uuid4().hex[:12]}",
            "rule_id": "CHK06",
            "category": "A02:2025",
            "title": "Possible unintended directory listing",
            "status": "Potential",
            "severity": "Informational",
            "confidence": "Multiple structural indicators",
            "impact": reason,
            "fix": (
                "Confirm whether directory browsing is intended. "
                "If not, disable autoindex and review access controls "
                "for the listed resources."
            ),
            "retest": (
                "Request the directory again and verify that its "
                "listing is no longer exposed when not intended."
            ),
            "affected_endpoints": [endpoint],
            "contributing_tests": [test_id],
            "evidence_refs": [evidence_id],
        })

    return test, evidence, findings
