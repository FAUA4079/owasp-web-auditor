import unittest

from auditor.planning.coverage import (
    build_plan,
    reconcile_plan,
    build_coverage,
)


def make_record(rule, category, status):
    return {
        "id": "test-example",
        "rule_id": rule,
        "category": category,
        "status": status,
        "reason": "Fixture reason",
        "endpoint": "http://lab.example/",
    }


class CoverageTests(unittest.TestCase):
    def test_empty_results_leave_all_categories_untested(self):
        coverage = build_coverage([])
        self.assertEqual(len(coverage["categories"]), 10)
        self.assertTrue(all(
            row["coverage"] == "Not Tested"
            for row in coverage["categories"]
        ))

    def test_no_issue_does_not_mean_full_category_pass(self):
        coverage = build_coverage([
            make_record("CHK03", "A02:2025", "No Issue Observed")
        ])
        row = next(
            item for item in coverage["categories"]
            if item["category"] == "A02:2025"
        )
        self.assertEqual(row["coverage"], "Partially Assessed")
        self.assertEqual(row["attempted_rules"], ["CHK03"])

    def test_skipped_check_does_not_count_as_attempted(self):
        coverage = build_coverage([
            make_record("CHK07", "A05:2025", "Not Tested")
        ])
        row = next(
            item for item in coverage["categories"]
            if item["category"] == "A05:2025"
        )
        self.assertEqual(row["coverage"], "Not Tested")
        self.assertEqual(row["attempted_rules"], [])
        self.assertEqual(row["skipped_rules"], ["CHK07"])

    def test_selected_rule_can_still_have_missing_results(self):
        plan = build_plan(
            "http://lab.example/search",
            reflection_param="q",
        )
        final = reconcile_plan(plan, [])
        rule = next(
            item for item in final["checks"]
            if item["rule_id"] == "CHK07"
        )
        self.assertEqual(rule["selection"], "selected")
        self.assertEqual(rule["record_state"], "missing_result")
