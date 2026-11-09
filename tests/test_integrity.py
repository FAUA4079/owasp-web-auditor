import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from auditor.verification.integrity import audit_run


def write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = Path(self.temp.name)

        for name in ("results", "evidence", "reports"):
            (self.run / name).mkdir()

        self.test = {
            "id": "test-one",
            "status": "Potential",
            "evidence_refs": ["ev-one"],
        }
        evidence = {
            "id": "ev-one",
            "test_id": "test-one",
            "observation": {"flag_present": False},
        }
        canonical = json.dumps(
            evidence,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()

        evidence["content_hash"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(canonical).hexdigest(),
            "scope": "Canonical JSON excluding content_hash",
        }

        write(self.run / "scan.json", {"request_count": 1})
        write(self.run / "request_ledger.json", [{"request_number": 1}])
        write(self.run / "results/tests.json", [self.test])
        write(self.run / "results/findings.json", [{
            "id": "finding-one",
            "contributing_tests": ["test-one"],
            "evidence_refs": ["ev-one"],
        }])
        write(self.run / "evidence/ev-one.json", evidence)

    def test_valid_links_and_hash_pass(self):
        self.assertEqual(audit_run(self.run), [])

    def test_modified_evidence_fails(self):
        path = self.run / "evidence/ev-one.json"
        evidence = json.loads(path.read_text())
        evidence["observation"]["flag_present"] = True
        write(path, evidence)

        self.assertTrue(any(
            "hash mismatch" in error for error in audit_run(self.run)
        ))

    def test_missing_evidence_fails(self):
        (self.run / "evidence/ev-one.json").unlink()
        self.assertTrue(any(
            "Missing evidence" in error for error in audit_run(self.run)
        ))

    def test_duplicate_test_id_fails(self):
        write(self.run / "results/tests.json", [self.test, self.test])
        self.assertTrue(any(
            "duplicate ID" in error for error in audit_run(self.run)
        ))
