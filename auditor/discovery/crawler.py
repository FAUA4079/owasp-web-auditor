from collections import deque
from urllib.parse import urlsplit

from auditor.core.http_client import ScanStopped
from auditor.discovery.parser import extract_inventory


MAX_TOTAL_RECORDS = 500


async def crawl_inventory(client, initial, max_depth, on_response=None):
    inventory = dict(initial)
    inventory["records"] = []
    inventory["limits_reached"] = list(
        initial.get("limits_reached", [])
    )
    inventory["crawl_stop_reason"] = None
    inventory["crawl_errors"] = []
    inventory["pages_fetched_by_crawler"] = 0
    inventory["pages_parsed"] = initial.get("pages_parsed", 0)
    inventory["limitations"] = [
        "Only query-free .html and .htm anchor links are followed.",
        "Forms are inventoried but never submitted.",
        "Security checks run only when a response handler is provided.",
        "Query values and form values are omitted.",
        "URL paths and input names are retained.",
        "JavaScript navigation is not evaluated.",
    ]

    queue = deque()
    seen = set()
    before_requests = client.request_count
    root = initial.get("source_url")

    if root:
        seen.add(root)

    def add_records(records, source_depth):
        for original in records:
            if len(inventory["records"]) >= MAX_TOTAL_RECORDS:
                inventory["limits_reached"].append(
                    "total_record_limit"
                )
                return

            record = dict(original)
            record["id"] = (
                f"endpoint-{len(inventory['records']) + 1:04d}"
            )
            record["source_depth"] = source_depth
            record["fetch_status"] = "not_requested"
            record["crawl_reason"] = None
            inventory["records"].append(record)

            url = record.get("url")

            if record.get("kind") != "link":
                record["crawl_reason"] = "form_not_submitted"
                continue

            if record.get("scope_decision") != "allowed" or not url:
                record["crawl_reason"] = "scope_or_url_rejected"
                continue

            if record.get("query_values_omitted"):
                record["crawl_reason"] = "query_url_not_supported"
                continue

            if not urlsplit(url).path.lower().endswith(
                (".html", ".htm")
            ):
                record["crawl_reason"] = "outside_static_html_profile"
                continue

            if url in seen:
                record["crawl_reason"] = "already_seen"
                continue

            if source_depth >= max_depth:
                record["crawl_reason"] = "depth_limit"
                inventory["limits_reached"].append("depth_limit")
                continue

            seen.add(url)
            record["fetch_status"] = "queued"
            queue.append((url, source_depth + 1, record))

    add_records(initial.get("records", []), 0)

    while queue:
        if "total_record_limit" in inventory["limits_reached"]:
            inventory["crawl_stop_reason"] = "total_record_limit"
            break

        url, depth, record = queue.popleft()

        try:
            # fetch() rechecks scope, budgets and every redirect.
            response = await client.fetch(url)

        except ScanStopped as exc:
            reason = str(exc)
            record["fetch_status"] = "stopped"
            record["crawl_reason"] = reason
            inventory["crawl_errors"].append({
                "endpoint_id": record["id"],
                "reason": reason,
            })

            if reason in {
                "request_budget_exhausted",
                "scan_deadline_reached",
            }:
                inventory["crawl_stop_reason"] = reason
                break

            continue

        inventory["pages_fetched_by_crawler"] += 1
        record["fetch_status"] = "fetched"
        record["response_status"] = response["status_code"]

        final_url = response["final_url"]
        if final_url in seen and final_url != url:
            record["crawl_reason"] = "redirect_destination_seen"
            continue

        seen.add(final_url)

        if on_response is not None:
            on_response(response)

        # Only expand successful responses as discovery content.
        # A successful status alone does not identify login pages.
        if not 200 <= response["status_code"] < 300:
            record["crawl_reason"] = "non_success_response"
            continue

        child = extract_inventory(response, client.check_scope)
        inventory["pages_parsed"] += child["pages_parsed"]
        inventory["limits_reached"].extend(
            child.get("limits_reached", [])
        )
        add_records(child["records"], depth)

    for _, _, record in queue:
        record["fetch_status"] = "not_requested"
        record["crawl_reason"] = (
            inventory["crawl_stop_reason"] or "crawl_stopped"
        )

    inventory["additional_requests"] = (
        client.request_count - before_requests
    )
    inventory["limits_reached"] = sorted(
        set(inventory["limits_reached"])
    )

    if initial.get("status") == "not_parsed":
        inventory["status"] = "not_parsed"
    elif (
        inventory["crawl_stop_reason"]
        or inventory["crawl_errors"]
        or inventory["limits_reached"]
    ):
        inventory["status"] = "partial"
    else:
        inventory["status"] = "completed_within_profile"

    return inventory
