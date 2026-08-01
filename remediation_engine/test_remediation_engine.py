"""
test_remediation_engine.py
---------------------------
Unit tests for the Week 2 Remediation Engine (Member 3).

Run with:
    python -m unittest test_remediation_engine.py -v
or simply:
    python test_remediation_engine.py
"""

import json
import unittest
from pathlib import Path

from engine import RemediationEngine

FIXTURES_DIR = Path(__file__).parent


class TestRemediationEngineBasicMatching(unittest.TestCase):
    def setUp(self):
        self.engine = RemediationEngine()

    def test_s3_public_bucket_matches_by_text(self):
        finding = {
            "id": "T1",
            "service": "S3",
            "resource": "test-bucket",
            "misconfiguration": "Public Bucket",
        }
        result = self.engine.get_recommendation(finding)
        self.assertEqual(result["recommendation_status"], "MATCHED")
        self.assertEqual(result["remediation_id"], "S3_PUBLIC_BUCKET")
        self.assertEqual(result["severity"], "Critical")
        self.assertIn("Block Public Access", result["recommendation"])
        self.assertTrue(len(result["remediation_steps"]) >= 1)

    def test_iam_admin_policy_matches(self):
        finding = {
            "service": "IAM",
            "misconfiguration": "User has AdministratorAccess policy",
        }
        result = self.engine.get_recommendation(finding)
        self.assertEqual(result["remediation_id"], "IAM_ADMIN_POLICY_ATTACHED")
        self.assertEqual(result["recommendation_status"], "MATCHED")

    def test_ec2_ssh_open_matches(self):
        finding = {
            "service": "EC2",
            "misconfiguration": "Security Group allows SSH (22) from 0.0.0.0/0",
        }
        result = self.engine.get_recommendation(finding)
        self.assertEqual(result["remediation_id"], "EC2_SSH_OPEN_TO_WORLD")
        self.assertEqual(result["severity"], "High")

    def test_match_is_case_and_whitespace_insensitive(self):
        finding = {
            "service": "  s3  ",
            "misconfiguration": "   public   bucket  ",
        }
        result = self.engine.get_recommendation(finding)
        self.assertEqual(result["remediation_id"], "S3_PUBLIC_BUCKET")

    def test_match_via_alias_text(self):
        finding = {
            "service": "EC2",
            "misconfiguration": "SSH Open to Internet",  # alias, not canonical text
        }
        result = self.engine.get_recommendation(finding)
        self.assertEqual(result["remediation_id"], "EC2_SSH_OPEN_TO_WORLD")

    def test_match_via_preferred_stable_id(self):
        finding = {
            "service": "S3",
            "misconfiguration": "some future wording that does not matter",
            "misconfiguration_id": "S3_ENCRYPTION_DISABLED",
        }
        result = self.engine.get_recommendation(finding)
        self.assertEqual(result["remediation_id"], "S3_ENCRYPTION_DISABLED")
        self.assertEqual(result["recommendation_status"], "MATCHED")


class TestRemediationEngineEdgeCases(unittest.TestCase):
    def setUp(self):
        self.engine = RemediationEngine()

    def test_unknown_misconfiguration_does_not_crash(self):
        finding = {
            "service": "IAM",
            "misconfiguration": "Totally new issue never seen before",
        }
        result = self.engine.get_recommendation(finding)
        self.assertEqual(result["recommendation_status"], "NOT_FOUND")
        self.assertIsNone(result["remediation_id"])
        self.assertEqual(result["remediation_steps"], [])

    def test_missing_fields_does_not_crash(self):
        finding = {}  # completely empty finding
        result = self.engine.get_recommendation(finding)
        self.assertEqual(result["recommendation_status"], "NOT_FOUND")

    def test_original_fields_are_preserved(self):
        finding = {
            "id": "F999",
            "service": "S3",
            "resource": "my-bucket",
            "misconfiguration": "Public Bucket",
            "risk_score": 88,
            "status": "Open",
        }
        result = self.engine.get_recommendation(finding)
        self.assertEqual(result["id"], "F999")
        self.assertEqual(result["resource"], "my-bucket")
        self.assertEqual(result["risk_score"], 88)
        self.assertEqual(result["status"], "Open")

    def test_input_dict_is_not_mutated(self):
        finding = {"service": "S3", "misconfiguration": "Public Bucket"}
        original_keys = set(finding.keys())
        self.engine.get_recommendation(finding)
        self.assertEqual(set(finding.keys()), original_keys)

    def test_explicit_severity_is_not_overridden(self):
        finding = {
            "service": "S3",
            "misconfiguration": "Public Bucket",
            "severity": "Custom-Override",
        }
        result = self.engine.get_recommendation(finding)
        self.assertEqual(result["severity"], "Custom-Override")


class TestBatchProcessing(unittest.TestCase):
    def setUp(self):
        self.engine = RemediationEngine()

    def test_process_findings_list(self):
        findings = [
            {"service": "S3", "misconfiguration": "Public Bucket"},
            {"service": "EC2", "misconfiguration": "IMDSv1 enabled"},
        ]
        results = self.engine.process_findings(findings)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["remediation_id"], "S3_PUBLIC_BUCKET")
        self.assertEqual(results[1]["remediation_id"], "EC2_IMDSV1_ENABLED")

    def test_process_full_scan_report_preserves_metadata(self):
        with open(FIXTURES_DIR / "sample_findings_input.json") as f:
            scan_report = json.load(f)

        result = self.engine.process_scan_report(scan_report)

        # scan_information and summary should pass through untouched
        self.assertEqual(result["scan_information"], scan_report["scan_information"])
        self.assertEqual(result["summary"], scan_report["summary"])

        # every finding should now have a recommendation_status
        self.assertEqual(len(result["findings"]), len(scan_report["findings"]))
        for finding in result["findings"]:
            self.assertIn("recommendation_status", finding)
            self.assertIn(finding["recommendation_status"], ("MATCHED", "NOT_FOUND"))

    def test_sample_report_known_matches(self):
        with open(FIXTURES_DIR / "sample_findings_input.json") as f:
            scan_report = json.load(f)
        result = self.engine.process_scan_report(scan_report)

        matched = [f for f in result["findings"] if f["recommendation_status"] == "MATCHED"]
        not_found = [f for f in result["findings"] if f["recommendation_status"] == "NOT_FOUND"]

        # 6 of the 7 sample findings are known issues, 1 (F007) is intentionally novel
        self.assertEqual(len(matched), 6)
        self.assertEqual(len(not_found), 1)
        self.assertEqual(not_found[0]["id"], "F007")


class TestKnowledgeBaseIntegrity(unittest.TestCase):
    """Sanity checks on the mapping data itself, so a bad edit to the JSON
    file gets caught by CI (relevant for Member 4's automation)."""

    def setUp(self):
        self.engine = RemediationEngine()

    def test_all_entries_loaded(self):
        self.assertEqual(len(self.engine.known_ids()), 14)

    def test_every_entry_has_required_fields(self):
        for rid in self.engine.known_ids():
            entry = self.engine.get_by_id(rid)
            for field in ("service", "misconfiguration", "severity", "recommendation", "remediation_steps"):
                self.assertIn(field, entry, f"{rid} missing '{field}'")
            self.assertTrue(len(entry["remediation_steps"]) > 0, f"{rid} has no remediation steps")

    def test_severity_values_are_valid(self):
        valid_severities = {"Critical", "High", "Medium", "Low"}
        for rid in self.engine.known_ids():
            entry = self.engine.get_by_id(rid)
            self.assertIn(entry["severity"], valid_severities, f"{rid} has invalid severity")


if __name__ == "__main__":
    unittest.main(verbosity=2)
