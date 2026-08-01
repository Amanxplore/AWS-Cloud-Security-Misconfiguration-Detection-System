# Remediation Recommendation Engine

**Project:** Cloud Security Misconfiguration Detection System
**Module:** Deliverable 3 — Remediation & Reporting
**Owner:** Member 3
**Status:** Week 2 — Functional prototype complete

## What this is

A small, dependency-free Python module that takes a misconfiguration
"finding" (the kind Member 1's AWS Scanner will produce) and returns it
enriched with:

- a human-readable **recommendation**
- a list of concrete **remediation_steps**
- a normalized **severity**
- a stable **remediation_id** for programmatic use (e.g. by Member 2's
  Risk Scoring Engine)

It works standalone today using mock scan data, and is designed to plug
directly into Member 1's real scanner output once that's ready, with no
changes needed on this end.

# Remediation & Reporting Module

**Project:** Cloud Security Misconfiguration Detection System
**Module:** Deliverable 3 — Remediation & Reporting
**Owner:** Member 3
**Status:** Week 3 — Report generation complete

## What this is

A dependency-free Python pipeline that takes raw AWS scan findings and
turns them into:

1. **Enriched findings** — each finding matched against a remediation
   knowledge base and tagged with severity, recommendation, and step-by-step
   fixes (Week 2).
2. **A JSON report** — machine-readable, for integrations and dashboards
   (Week 3).
3. **An HTML report** — a single self-contained, styled HTML file for
   human review (Week 3).

It works standalone today using mock scan data, and plugs directly into
Member 1's real scanner output once that's ready, with no changes needed
on this end.

## Files

| File | Purpose |
|---|---|
| `remediation_mapping.json` | Knowledge base: 14 known AWS misconfigurations (IAM, S3, EC2) mapped to severity + recommendation + remediation steps. |
| `engine.py` | `RemediationEngine` — matches findings against the knowledge base and enriches them. **(Week 2)** |
| `json_report.py` | Builds the final JSON report from enriched findings, with a freshly computed severity summary. **(Week 3)** |
| `html_report.py` | Builds a self-contained, styled HTML report from enriched findings. **(Week 3)** |
| `generate_reports.py` | End-to-end CLI: raw scan report → engine → JSON report + HTML report, in one command. **(Week 3)** |
| `sample_findings_input.json` | Mock scan report (7 findings) shaped like Member 1's expected scanner output. |
| `sample_recommendations_output.json` | Verified output of the Week 2 engine run on the sample input. |
| `sample_generated_report.json` | Verified Week 3 JSON report, generated from the sample data. |
| `sample_generated_report.html` | Verified Week 3 HTML report, generated from the sample data — open directly in a browser. |
| `test_remediation_engine.py` | 17 unit tests for the Week 2 engine. |
| `test_report_generators.py` | 15 unit tests for the Week 3 report generators, including an end-to-end pipeline test. |

## How to run it

```bash
# Run the full pipeline: raw findings -> enriched -> JSON + HTML reports
python generate_reports.py sample_findings_input.json output/
# writes output/generated_report.json and output/generated_report.html

# Run all tests (32 total)
python -m unittest test_remediation_engine.py test_report_generators.py -v
```

No pip installs required — standard library only.

## How to use it in code

```python
from engine import RemediationEngine
from json_report import generate_json_report
from html_report import generate_html_report

engine = RemediationEngine()
enriched_report = engine.process_scan_report(raw_scan_report)  # from Member 1

generate_json_report(enriched_report, "report.json")
generate_html_report(enriched_report, "report.html")
```

## Integration contract (for Member 1, Member 2, Member 4)

**For Member 1 (AWS Scanner):** unchanged from Week 2 — emit findings with
`service`, `resource`, `misconfiguration` (or `misconfiguration_id`). Once
your real scan report replaces `sample_findings_input.json`, both reports
generate automatically with no code changes on this end.

**For Member 2 (Risk Scoring Engine):** the `risk_score` field you produce
is passed straight through into both the JSON and HTML reports and
displayed per-finding. `severity` is currently sourced from the
remediation knowledge base — if you want your calculated score to also
drive severity/summary counts, that's a one-line change in
`json_report.compute_summary` and easy to wire up during Week 4
integration.

**For Member 4 (CI/Automation):** `generate_reports.py` is a single CLI
entry point suitable for a pipeline step (`python generate_reports.py
<scan_output.json> <output_dir>`). All 32 tests run with plain
`python -m unittest`, no dependencies to install.

## Known limitations (to close in Week 4)

- Severity/summary counts are currently derived from the knowledge base
  rather than Member 2's risk scores — Week 4 integration will decide the
  final source of truth.
- HTML styling is functional but not yet visually polished — Week 4 covers
  layout improvements.
- Findings with `recommendation_status: NOT_FOUND` are clearly flagged in
  both reports but not yet routed anywhere for manual triage.

## Deliverables checklist

**Week 2**
- [x] Functional remediation engine prototype
- [x] Recommendation generation for IAM, S3, EC2 findings
- [x] Sample input/output files
- [x] Unit tests (17)

**Week 3**
- [x] JSON report generation module
- [x] HTML report generation module
- [x] Sample generated reports for review
- [x] Unit tests (15) + end-to-end pipeline test

