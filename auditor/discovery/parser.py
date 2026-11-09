from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from auditor.core.http_client import ScanStopped


MAX_RECORDS = 200
MAX_INPUTS = 100


def describe_destination(raw, base_url, check_scope):
    record = {
        "url": None,
        "query_names": [],
        "query_values_omitted": False,
        "scope_decision": "unsupported",
        "reason": None,
    }

    try:
        if "\\" in raw or any(
            char.isspace() or ord(char) < 32 for char in raw
        ):
            raise ValueError("Invalid URL characters")

        absolute = urljoin(base_url, raw)
        parts = urlsplit(absolute)

        if parts.scheme not in {"http", "https"} or not parts.hostname:
            record["reason"] = "unsupported_scheme_or_host"
            return record

        if parts.username is not None or parts.password is not None:
            record["reason"] = "credentials_in_url"
            return record

        pairs = parse_qsl(
            parts.query,
            keep_blank_values=True,
            max_num_fields=100,
        )

        record["query_names"] = sorted({name for name, _ in pairs})
        record["query_values_omitted"] = bool(parts.query)

        # This is a display/inventory URL, not a replacement request URL.
        clean_url = urlunsplit((
            parts.scheme,
            parts.netloc,
            parts.path or "/",
            "",
            "",
        ))

        record["url"] = clean_url

        try:
            check_scope(clean_url)
            record["scope_decision"] = "allowed"
        except ScanStopped as exc:
            record["scope_decision"] = "blocked"
            record["reason"] = str(exc)

    except ValueError:
        record["reason"] = "invalid_or_over_limit_url"

    return record


def extract_inventory(response, check_scope):
    source = response["final_url"]
    content_type = response["headers"].get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()

    inventory = {
        "source_url": source,
        "status": "not_parsed",
        "reason": None,
        "pages_parsed": 0,
        "additional_requests": 0,
        "records": [],
        "limits_reached": [],
        "limitations": [
            "Single-response HTML inventory only; no crawling.",
            "Forms are recorded, never submitted.",
            "Query and form values are not retained.",
            "Query-stripped URLs must not be replayed as original URLs.",
            "JavaScript and external form controls are not evaluated.",
            "URL paths and input names are retained; full redaction is pending.",
        ],
    }

    if media_type not in {"text/html", "application/xhtml+xml"}:
        inventory["reason"] = "response_not_declared_html"
        return inventory

    from auditor.checks.directory_listing import review_directory_listing

    listing_test, _, _ = review_directory_listing(response)
    if listing_test["status"] == "Potential":
        inventory["status"] = "not_parsed"
        inventory["reason"] = "recognized_listing_entries_not_expanded"
        inventory["limitations"].append(
            "Recognized directory-listing entries are not inventoried or crawled."
        )
        return inventory

    soup = BeautifulSoup(response["body"], "html.parser")
    inventory["status"] = "parsed"
    inventory["pages_parsed"] = 1

    # Relative links may be affected by the document's first base href.
    base_tag = soup.find("base", href=True)
    base_url = source
    if base_tag:
        base_url = urljoin(source, str(base_tag["href"]).strip())

    candidates = soup.find_all(["a", "form"], limit=MAX_RECORDS + 1)
    if len(candidates) > MAX_RECORDS:
        inventory["limits_reached"].append("record_limit")

    for index, tag in enumerate(candidates[:MAX_RECORDS], start=1):
        is_form = tag.name == "form"

        if not is_form and not tag.has_attr("href"):
            continue

        if is_form:
            action = str(tag.get("action", "")).strip()
            # Empty form actions refer to the current document.
            raw = action if action else source
            declared_method = str(tag.get("method", "get")).lower()
            method = (
                declared_method.upper()
                if declared_method in {"get", "post", "dialog"}
                else "GET"
            )
        else:
            raw = str(tag.get("href", "")).strip()
            method = "GET"

        record = describe_destination(raw, base_url, check_scope)
        record.update({
            "id": f"endpoint-{index:04d}",
            "kind": "form" if is_form else "link",
            "method": method,
            "discovery_source": source,
            "source_depth": 0,
            "fetch_status": "not_requested",
            "inputs": [],
        })

        if is_form:
            controls = tag.find_all(
                ["input", "select", "textarea", "button"],
                limit=MAX_INPUTS + 1,
            )

            if len(controls) > MAX_INPUTS:
                inventory["limits_reached"].append("input_limit")

            for control in controls[:MAX_INPUTS]:
                name = control.get("name")
                if not name:
                    continue

                record["inputs"].append({
                    "name": str(name),
                    "element": control.name,
                    "type": str(
                        control.get(
                            "type",
                            "text" if control.name == "input"
                            else control.name,
                        )
                    ),
                    "location": (
                        "query" if method == "GET"
                        else "body" if method == "POST"
                        else "not_submitted"
                    ),
                })

        inventory["records"].append(record)

    inventory["limits_reached"] = sorted(
        set(inventory["limits_reached"])
    )

    if inventory["limits_reached"]:
        inventory["status"] = "partial"

    return inventory
