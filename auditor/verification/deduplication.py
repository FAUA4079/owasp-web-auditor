from copy import deepcopy


def deduplicate_findings(findings):
    groups = {}

    for finding in findings:
        key = tuple(
            finding.get(field, "")
            for field in (
                "rule_id",
                "category",
                "title",
                "status",
                "severity",
                "confidence",
                "impact",
                "fix",
                "retest",
            )
        )

        if key not in groups:
            grouped = deepcopy(finding)
            grouped["source_finding_ids"] = []
            grouped["affected_endpoints"] = []
            grouped["contributing_tests"] = []
            grouped["evidence_refs"] = []
            groups[key] = grouped

        grouped = groups[key]

        for field in (
            "affected_endpoints",
            "contributing_tests",
            "evidence_refs",
        ):
            for value in finding.get(field, []):
                if value not in grouped[field]:
                    grouped[field].append(value)

        source_ids = finding.get(
            "source_finding_ids", [finding["id"]]
        )
        for source_id in source_ids:
            if source_id not in grouped["source_finding_ids"]:
                grouped["source_finding_ids"].append(source_id)

    return list(groups.values())
