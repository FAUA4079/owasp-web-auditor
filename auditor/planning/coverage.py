from urllib.parse import urlsplit


CATEGORIES = [
    ("A01:2025", "Broken Access Control",
     "Role sessions, ownership rules and authorization workflows."),
    ("A02:2025", "Security Misconfiguration",
     "Deployment configuration and contextual confirmation."),
    ("A03:2025", "Software Supply Chain Failures",
     "Dependency inventory, SBOM and build-pipeline evidence."),
    ("A04:2025", "Cryptographic Failures",
     "Full TLS configuration, storage encryption and key management."),
    ("A05:2025", "Injection",
     "Contextual validation beyond harmless input reflection."),
    ("A06:2025", "Insecure Design",
     "Business rules, architecture and threat modelling."),
    ("A07:2025", "Authentication Failures",
     "Test accounts and authentication/session workflows."),
    ("A08:2025", "Software or Data Integrity Failures",
     "Trusted-data and software-update workflows."),
    ("A09:2025", "Security Logging and Alerting Failures",
     "Backend logs and alert evidence."),
    ("A10:2025", "Mishandling of Exceptional Conditions",
     "Broader failure paths, recovery behaviour and internal evidence."),
]

RULES = {
    "CHK01": {
        "category": "A04:2025",
        "scope": "Supplied HTTP root and its permitted redirect chain.",
        "prerequisites": "HTTP root URL and successful bounded retrieval.",
    },
    "CHK02": {
        "category": "A02:2025",
        "scope": "Framing-policy indicators on fetched HTML responses.",
        "prerequisites": "A complete response declared as HTML.",
    },
    "CHK03": {
        "category": "A02:2025",
        "scope": "Content-Type and nosniff observations on fetched responses.",
        "prerequisites": "A complete response with accessible headers.",
    },
    "CHK04": {
        "category": "A02:2025",
        "scope": "Supported attributes in final-response Set-Cookie fields.",
        "prerequisites": "A complete response containing Set-Cookie.",
    },
    "CHK05": {
        "category": "A02:2025",
        "scope": "Selected Python/PHP error structures in bounded text.",
        "prerequisites": "A complete declared HTML or plain-text response.",
    },
    "CHK06": {
        "category": "A02:2025",
        "scope": "Common directory-listing structures at fetched directories.",
        "prerequisites": "Successful HTML response at a trailing-slash URL.",
    },
    "CHK07": {
        "category": "A05:2025",
        "scope": "Exact harmless-marker reflection in one selected parameter.",
        "prerequisites": "Explicit read-only parameter and comparable responses.",
    },
    "CHK08": {
        "category": "A10:2025",
        "scope": "One numeric baseline and one malformed query value.",
        "prerequisites": "Explicit numeric read-only parameter and valid baseline.",
    },
}

AUTH_RULES = {
    'CHK09': {'category':'A01:2025', 'scope':'Declared private orders, owner and unrelated customer controls.', 'prerequisites':'Verified customer accounts and declared ownership.'},
    'CHK10': {'category':'A01:2025', 'scope':'Anonymous access to declared private orders.', 'prerequisites':'Verified owner control and declared private resource.'},
    'CHK11': {'category':'A05:2025', 'scope':'Two catalogue SQL boolean pairs and stable baseline controls.', 'prerequisites':'AuditShop JSON catalogue with a stable nonempty baseline.'},
    'CHK12': {'category':'A07:2025', 'scope':'One replay of an old session after acknowledged logout.', 'prerequisites':'Verified account identity and logout endpoint.'},
    'CHK13': {'category':'A01:2025', 'scope':'Explicit /api/rbac/<slug> resource for two verified roles under operator-approved access policy.', 'prerequisites':'Explicit --rbac-policy with two verified account roles and lab resource marker.'},
}

VALID_STATUSES = {
    "Confirmed",
    "Potential",
    "Inconclusive",
    "No Issue Observed",
    "Not Tested",
}


def build_plan(target, reflection_param=None, exception_param=None, selected_checks=None):
    parts = urlsplit(target)
    entries = []

    for rule_id, metadata in RULES.items():
        selection = "conditional"
        reason = "Evaluate prerequisites on each available response."

        if rule_id == "CHK01":
            eligible = (
                parts.scheme == "http"
                and parts.path in {"", "/"}
                and not parts.query
            )
            selection = "selected" if eligible else "not_selected"
            reason = (
                "HTTP root supplied."
                if eligible else "An HTTP root URL is required."
            )

        elif rule_id in {"CHK07", "CHK08"}:
            parameter = (
                reflection_param if rule_id == "CHK07"
                else exception_param
            )
            selection = "selected" if parameter else "not_selected"
            reason = (
                "Operator selected a read-only parameter."
                if parameter else "No parameter selected."
            )

        if selected_checks is not None and rule_id not in selected_checks:
            selection = 'not_selected'
            reason = 'Disabled by operator check selection.'

        entries.append({
            "rule_id": rule_id,
            **metadata,
            "selection": selection,
            "selection_reason": reason,
        })

    return {
        "level": "rule",
        "target": target,
        "limitations": [
            "This is a pre-run rule plan, not an endpoint-level schedule.",
            "Conditional checks depend on responses obtained during the run.",
            "Selection does not mean a check completed.",
        ],
        "checks": entries,
    }


def reconcile_plan(plan, tests):
    result = dict(plan)
    result["checks"] = []

    for entry in plan["checks"]:
        matching = [
            test for test in tests
            if test["rule_id"] == entry["rule_id"]
        ]

        updated = dict(entry)
        updated["test_ids"] = [test["id"] for test in matching]
        updated["outcomes"] = [
            {
                "test_id": test["id"],
                "endpoint": test.get("endpoint"),
                "status": test["status"],
                "reason": test.get("reason"),
            }
            for test in matching
        ]
        updated["record_state"] = (
            "results_recorded" if matching else "missing_result"
        )
        result["checks"].append(updated)

    return result


def build_coverage(tests):
    rules = {**RULES, **AUTH_RULES}
    for test in tests:
        rule_id = test["rule_id"]
        if rule_id not in rules:
            raise ValueError(f"Unknown coverage rule: {rule_id}")
        if test["status"] not in VALID_STATUSES:
            raise ValueError("Unknown test outcome.")
        if test["category"] != rules[rule_id]["category"]:
            raise ValueError(f"Category mismatch for {rule_id}")

    rows = []

    for category_id, name, additional_evidence in CATEGORIES:
        supported_rules = [
            rule for rule, metadata in rules.items()
            if metadata["category"] == category_id
        ]
        matching = [
            test for test in tests
            if test["rule_id"] in supported_rules
        ]
        attempted = [
            test for test in matching if test["status"] != "Not Tested"
        ]
        skipped = [
            test for test in matching if test["status"] == "Not Tested"
        ]

        counts = {
            status: sum(test["status"] == status for test in matching)
            for status in sorted(VALID_STATUSES)
        }

        rows.append({
            "category": category_id,
            "name": name,
            "coverage": (
                "Partially Assessed" if attempted else "Not Tested"
            ),
            "supported_rules": supported_rules,
            "attempted_rules": sorted({
                test["rule_id"] for test in attempted
            }),
            "skipped_rules": sorted({
                test["rule_id"] for test in skipped
            }),
            "missing_result_rules": sorted(
                set(supported_rules)
                - {test["rule_id"] for test in matching}
            ),
            "outcome_counts": counts,
            "test_ids": [test["id"] for test in matching],
            "declared_check_scopes": [
                rules[rule]["scope"] for rule in supported_rules
            ],
            "skipped_reasons": sorted({
                test.get("reason") or "Reason not recorded"
                for test in skipped
            }),
            "additional_evidence_needed": additional_evidence,
            "limitations": (
                "No implemented rule is mapped to this category."
                if not supported_rules else
                "Coverage is limited to recorded checks. Inconclusive "
                "attempts do not establish a reliable security conclusion."
            ),
        })

    return {
        "framework": "OWASP Top 10 2025",
        "note": (
            "Coverage is not a security score. No Issue Observed applies "
            "only to the recorded test. No category is certified as secure."
        ),
        "categories": rows,
    }
