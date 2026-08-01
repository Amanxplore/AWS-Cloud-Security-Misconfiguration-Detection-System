"""
test_report_generators.py
---------------------------
Unit tests for the Week 3 report generators (json_report.py, html_report.py).

Run with:
    python -m unittest test_report_generators.py -v
"""

import json
import unittest
from pathlib import Path

from engine import RemediationEngine
from json_report import build_json_report, compute_summary
from html_report import build_html_report

FIXTURES_DIR = Path(__file__).parent


def _load_enriched_sample():
    engine = RemediationEngine()
    with open(FIXTURES_DIR / "sample_findings_input.json") as f:
        raw = json.load(f)
    return engine.process_scan_report(raw)


class TestComputeSummary(unittest.TestCase):
    def test_counts_by_severity(self):
        findings = [
            {"severity": "Critical"},
            {"severity": "Critical"},
            {"severity": "High"},
            {"severity": "Medium"},
            {"severity": "Low"},
        ]
        summary = compute_summary(findings)
        self.assertEqual(summary["critical"], 2)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["low"], 1)
        self.assertEqual(summary["total_findings"], 5)

    def test_empty_findings(self):
        summary = compute_summary([])
        self.assertEqual(summary["total_findings"], 0)
        self.assertEqual(summary["critical"], 0)

    def test_unknown_severity_falls_back_to_low(self):
        summary = compute_summary([{"severity": "Weird"}])
        self.assertEqual(summary["low"], 1)


class TestJsonReport(unittest.TestCase):
    def setUp(self):
        self.enriched = _load_enriched_sample()

    def test_report_has_required_top_level_keys(self):
        report = build_json_report(self.enriched)
        for key in ("report_type", "generated_at", "scan_information", "summary", "findings"):
            self.assertIn(key, report)

    def test_scan_information_passed_through(self):
        report = build_json_report(self.enriched)
        self.assertEqual(report["scan_information"], self.enriched["scan_information"])

    def test_summary_matches_actual_findings(self):
        report = build_json_report(self.enriched)
        recomputed = compute_summary(self.enriched["findings"])
        self.assertEqual(report["summary"], recomputed)

    def test_findings_preserved(self):
        report = build_json_report(self.enriched)
        self.assertEqual(len(report["findings"]), len(self.enriched["findings"]))
        self.assertEqual(report["findings"][0]["id"], self.enriched["findings"][0]["id"])

    def test_report_is_json_serializable(self):
        report = build_json_report(self.enriched)
        # will raise if not serializable
        json.dumps(report)


class TestHtmlReport(unittest.TestCase):
    def setUp(self):
        self.enriched = _load_enriched_sample()
        self.html = build_html_report(self.enriched)

    def test_contains_doctype_and_closing_tags(self):
        self.assertTrue(self.html.strip().startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", self.html)

    def test_scan_info_rendered(self):
        self.assertIn("SCAN-001", self.html)
        self.assertIn("ap-south-1", self.html)

    def test_all_findings_rendered(self):
        for i in range(1, 8):
            self.assertIn(f"Finding #{i}", self.html)

    def test_matched_finding_shows_recommendation(self):
        self.assertIn("Enable Block Public Access", self.html)

    def test_not_found_finding_shows_manual_review_note(self):
        self.assertIn("manual review", self.html)

    def test_html_special_characters_are_escaped(self):
        enriched = {
            "scan_information": {"scan_id": "S&<1>", "scan_date": "", "aws_account_id": "", "region": ""},
            "findings": [
                {
                    "service": "S3",
                    "resource": "<script>alert(1)</script>",
                    "misconfiguration": "Test & Verify",
                    "severity": "Low",
                    "recommendation": "n/a",
                    "remediation_steps": [],
                }
            ],
        }
        html_out = build_html_report(enriched)
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertIn("&lt;script&gt;", html_out)


class TestEndToEndPipeline(unittest.TestCase):
    """Confirms engine output feeds cleanly into both report generators
    with no shape mismatches - this is the exact chain Member 4's CI
    pipeline will run."""

    def test_engine_output_feeds_both_generators_without_error(self):
        enriched = _load_enriched_sample()
        json_report = build_json_report(enriched)
        html_report = build_html_report(enriched)

        self.assertEqual(json_report["summary"]["total_findings"], 7)
        self.assertIn("Finding #7", html_report)  # the intentionally unmatched one


if __name__ == "__main__":
    unittest.main(verbosity=2)
