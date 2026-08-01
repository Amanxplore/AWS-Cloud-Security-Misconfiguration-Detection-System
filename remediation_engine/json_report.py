"""
json_report.py
---------------
JSON Report Generator
Deliverable 3 (Member 3) - Week 3

Purpose
-------
Takes an enriched scan report (output of engine.process_scan_report from
Week 2) and produces a final, polished JSON report file: consistent
structure, a freshly computed summary (so it can never drift out of sync
with the actual findings), and a generation timestamp.

This is intentionally a thin layer on top of the Week 2 engine output -
report generation is kept separate from recommendation logic so each piece
stays easy to test and easy for teammates to reuse independently.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def compute_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Recompute severity counts directly from the findings list, so the
    summary always reflects reality rather than a value someone forgot to
    update by hand."""
    counts = {sev.lower(): 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        severity = str(finding.get("severity", "")).strip().title()
        key = severity.lower() if severity in SEVERITY_ORDER else "low"
        counts[key] = counts.get(key, 0) + 1
    counts["total_findings"] = len(findings)
    return counts


def build_json_report(enriched_report: Dict[str, Any]) -> Dict[str, Any]:
    """Return a new dict representing the final JSON report. Does not
    mutate the input."""
    findings = enriched_report.get("findings", [])

    report = {
        "report_type": "json",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_information": enriched_report.get("scan_information", {}),
        "summary": compute_summary(findings),
        "findings": findings,
    }
    return report


def generate_json_report(enriched_report: Dict[str, Any], output_path: str) -> Dict[str, Any]:
    """Build the JSON report and write it to disk. Returns the report dict
    as well, in case the caller wants to chain further processing."""
    report = build_json_report(enriched_report)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python json_report.py <enriched_report.json> <output_report.json>")
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]

    with open(input_path, "r", encoding="utf-8") as f:
        enriched = json.load(f)

    generate_json_report(enriched, output_path)
    print(f"JSON report written to {output_path}")
