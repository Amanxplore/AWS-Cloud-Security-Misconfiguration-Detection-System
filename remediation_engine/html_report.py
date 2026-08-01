"""
html_report.py
---------------
HTML Report Generator
Deliverable 3 (Member 3) - Week 3

Purpose
-------
Takes an enriched scan report (output of engine.process_scan_report from
Week 2) and produces a single, self-contained, human-readable HTML report:
scan info, a color-coded severity summary, and one detail card per finding
with its recommendation and remediation steps.

No templating libraries required (stdlib only) so it drops into any
teammate's environment without extra installs. Styling is embedded inline
so the output is a single portable .html file.
"""

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .json_report import compute_summary, SEVERITY_ORDER

SEVERITY_COLORS = {
    "Critical": "#C00000",
    "High": "#E36C09",
    "Medium": "#BF8F00",
    "Low": "#375623",
}

PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cloud Security Assessment Report</title>
<style>
  body {{
    font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    background: #f5f6f8;
    color: #1a1a1a;
    margin: 0;
    padding: 32px;
  }}
  .container {{
    max-width: 900px;
    margin: 0 auto;
    background: #ffffff;
    border-radius: 8px;
    padding: 32px 40px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
  }}
  h1 {{
    color: #1F3864;
    text-align: center;
    margin-bottom: 4px;
  }}
  .subtitle {{
    text-align: center;
    color: #666;
    margin-bottom: 28px;
    font-size: 14px;
  }}
  table.info {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 28px;
  }}
  table.info td {{
    border: 1px solid #ddd;
    padding: 8px 12px;
    font-size: 14px;
  }}
  table.info td.label {{
    background: #EDEDED;
    font-weight: 600;
    width: 200px;
  }}
  .summary {{
    display: flex;
    gap: 12px;
    margin-bottom: 32px;
  }}
  .badge {{
    flex: 1;
    text-align: center;
    padding: 16px 8px;
    border-radius: 6px;
    color: white;
  }}
  .badge .count {{
    font-size: 28px;
    font-weight: 700;
    display: block;
  }}
  .badge .label {{
    font-size: 12px;
    letter-spacing: 0.05em;
  }}
  h2.section-title {{
    color: #1F3864;
    border-bottom: 2px solid #1F3864;
    padding-bottom: 6px;
    margin-top: 36px;
  }}
  .finding {{
    border: 1px solid #ddd;
    border-radius: 6px;
    margin-bottom: 20px;
    overflow: hidden;
  }}
  .finding-header {{
    padding: 12px 16px;
    color: white;
    font-weight: 700;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .finding-body {{
    padding: 16px;
  }}
  .finding-body table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 14px;
  }}
  .finding-body table td {{
    border: 1px solid #eee;
    padding: 6px 10px;
    font-size: 14px;
  }}
  .finding-body table td.label {{
    background: #f7f7f7;
    font-weight: 600;
    width: 160px;
  }}
  .finding-body ul {{
    margin: 6px 0 0 0;
    padding-left: 20px;
  }}
  .finding-body li {{
    margin-bottom: 4px;
    font-size: 14px;
  }}
  .not-found {{
    background: #f7f7f7;
    color: #888;
    font-style: italic;
    font-size: 13px;
  }}
  .footer {{
    text-align: center;
    color: #999;
    margin-top: 32px;
    border-top: 1px solid #ccc;
    padding-top: 12px;
    font-size: 13px;
    letter-spacing: 0.05em;
  }}
</style>
</head>
<body>
<div class="container">
  <h1>Cloud Security Assessment Report</h1>
  <div class="subtitle">Generated: {generated_at}</div>

  <table class="info">
    <tr><td class="label">Scan ID</td><td>{scan_id}</td></tr>
    <tr><td class="label">Scan Date</td><td>{scan_date}</td></tr>
    <tr><td class="label">AWS Account</td><td>{aws_account_id}</td></tr>
    <tr><td class="label">Region</td><td>{region}</td></tr>
  </table>

  <h2 class="section-title">Summary</h2>
  <div class="summary">
    {summary_badges}
  </div>

  <h2 class="section-title">Findings</h2>
  {findings_html}

  <div class="footer">END OF REPORT</div>
</div>
</body>
</html>
"""

FINDING_TEMPLATE = """
  <div class="finding">
    <div class="finding-header" style="background:{color};">
      <span>Finding #{index} &middot; {service}</span>
      <span>{severity} &middot; Risk {risk_score}</span>
    </div>
    <div class="finding-body">
      <table>
        <tr><td class="label">Resource</td><td>{resource}</td></tr>
        <tr><td class="label">Issue</td><td>{misconfiguration}</td></tr>
        <tr><td class="label">Status</td><td>{status}</td></tr>
      </table>
      <strong>Recommendation</strong>
      <p>{recommendation}</p>
      {steps_html}
    </div>
  </div>
"""

NOT_FOUND_NOTE = '<p class="not-found">No matching entry in the remediation knowledge base yet - flagged for manual review.</p>'


def _esc(value: Any) -> str:
    return html.escape(str(value)) if value is not None else ""


def _badge_html(label: str, count: int, color: str) -> str:
    return (
        f'<div class="badge" style="background:{color};">'
        f'<span class="count">{count}</span>'
        f'<span class="label">{label.upper()}</span>'
        f"</div>"
    )


def _finding_html(index: int, finding: Dict[str, Any]) -> str:
    severity = finding.get("severity", "Low")
    color = SEVERITY_COLORS.get(severity, "#555555")

    steps = finding.get("remediation_steps", [])
    if steps:
        items = "".join(f"<li>{_esc(step)}</li>" for step in steps)
        steps_html = f"<strong>Remediation Steps</strong><ul>{items}</ul>"
    else:
        steps_html = NOT_FOUND_NOTE if finding.get("recommendation_status") == "NOT_FOUND" else ""

    return FINDING_TEMPLATE.format(
        index=index,
        service=_esc(finding.get("service", "Unknown")),
        color=color,
        severity=_esc(severity).upper(),
        risk_score=_esc(finding.get("risk_score", "N/A")),
        resource=_esc(finding.get("resource", "N/A")),
        misconfiguration=_esc(finding.get("misconfiguration", "N/A")),
        status=_esc(finding.get("status", "Open")),
        recommendation=_esc(finding.get("recommendation", "")),
        steps_html=steps_html,
    )


def build_html_report(enriched_report: Dict[str, Any]) -> str:
    """Return the full HTML document as a string. Pure function - no I/O,
    which makes it easy to unit test."""
    scan_info = enriched_report.get("scan_information", {})
    findings = enriched_report.get("findings", [])
    summary = compute_summary(findings)

    badge_colors = {
        "critical": "#C00000",
        "high": "#E36C09",
        "medium": "#BF8F00",
        "low": "#375623",
    }
    summary_badges = "".join(
        _badge_html(sev, summary.get(sev, 0), badge_colors[sev]) for sev in ["critical", "high", "medium", "low"]
    )

    findings_html = "".join(_finding_html(i + 1, f) for i, f in enumerate(findings))
    if not findings_html:
        findings_html = "<p>No findings to display.</p>"

    return PAGE_TEMPLATE.format(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        scan_id=_esc(scan_info.get("scan_id", "N/A")),
        scan_date=_esc(scan_info.get("scan_date", "N/A")),
        aws_account_id=_esc(scan_info.get("aws_account_id", "N/A")),
        region=_esc(scan_info.get("region", "N/A")),
        summary_badges=summary_badges,
        findings_html=findings_html,
    )


def generate_html_report(enriched_report: Dict[str, Any], output_path: str) -> str:
    """Build the HTML report and write it to disk. Returns the HTML string
    as well, in case the caller wants it directly (e.g. to email or
    render inline)."""
    html_content = build_html_report(enriched_report)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return html_content


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 3:
        print("Usage: python html_report.py <enriched_report.json> <output_report.html>")
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]

    with open(input_path, "r", encoding="utf-8") as f:
        enriched = json.load(f)

    generate_html_report(enriched, output_path)
    print(f"HTML report written to {output_path}")
