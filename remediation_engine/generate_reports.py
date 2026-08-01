"""
generate_reports.py
--------------------
End-to-end pipeline: raw scan report -> Remediation Engine (Week 2) ->
JSON report + HTML report (Week 3).

This is the script Member 4 can wire into CI, and the one to point at
Member 1's real scanner output once it's ready - just swap the input file.

Usage:
    python generate_reports.py <input_scan_report.json> <output_dir>

Example:
    python generate_reports.py sample_findings_input.json output/
"""

import json
import sys
from pathlib import Path

from engine import RemediationEngine
from json_report import generate_json_report
from html_report import generate_html_report


def run_pipeline(input_path: str, output_dir: str) -> None:
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)

    with open(input_path, "r", encoding="utf-8") as f:
        raw_scan_report = json.load(f)

    engine = RemediationEngine()
    enriched_report = engine.process_scan_report(raw_scan_report)

    json_path = output_dir_path / "generated_report.json"
    html_path = output_dir_path / "generated_report.html"

    generate_json_report(enriched_report, str(json_path))
    generate_html_report(enriched_report, str(html_path))

    total = len(enriched_report.get("findings", []))
    matched = sum(1 for f in enriched_report["findings"] if f.get("recommendation_status") == "MATCHED")

    print(f"Processed {total} findings ({matched} matched, {total - matched} unmatched).")
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python generate_reports.py <input_scan_report.json> <output_dir>")
        sys.exit(1)

    run_pipeline(sys.argv[1], sys.argv[2])
