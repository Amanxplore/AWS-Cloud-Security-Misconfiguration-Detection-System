"""
Cloud Misconfiguration Detection System — Main Entry Point
-----------------------------------------------------------
Orchestrates all AWS security scanners (IAM, S3, EC2, Lambda) and feeds the
raw findings through the Risk Scoring Engine to produce scored,
prioritized reports.

Output:
    Each scan produces TWO timestamped files in the findings/ directory:
      - scan_YYYY-MM-DD_HH-MM-SS.json   → raw scanner findings
      - risk_YYYY-MM-DD_HH-MM-SS.json   → risk-scored findings with posture score
    Files are never overwritten — they stack up as scan history.

Workflow:
    1. Run selected scanners → collect raw findings → save scan_ file
    2. Pass raw findings through the risk scoring engine
       (adds risk_score, severity_label, compound_risk detection)
    3. Compute overall security posture score (0–100) → save risk_ file
    4. Run Remediation Engine -> enrich findings and generate HTML report.

Usage:
    python main.py                          # Scan all services
    python main.py --services iam s3        # Scan only IAM and S3
    python main.py --skip-scoring           # Raw findings only, no risk file
"""

import argparse
import datetime
import json
import os
import sys
import time
import boto3
from botocore.exceptions import ClientError

from scanners import IAMScanner, S3Scanner, EC2Scanner, LambdaScanner
from risk_scoring import score_findings, enrich_scanner_findings
from remediation_engine.engine import RemediationEngine
from remediation_engine.html_report import generate_html_report
from remediation_engine.auto_remediate import run_auto_remediation


# ── Scanner registry ─────────────────────────────────────────────────────────
SCANNER_MAP = {
    "iam": ("IAM", IAMScanner),
    "s3": ("S3", S3Scanner),
    "ec2": ("EC2", EC2Scanner),
    "lambda": ("Lambda", LambdaScanner),
}

BASE_OUTPUT_DIR = os.environ.get("RISK_ENGINE_OUTPUT_DIR", os.path.dirname(__file__))
FINDINGS_DIR = os.path.join(BASE_OUTPUT_DIR, "findings")
RISK_DIR = os.path.join(BASE_OUTPUT_DIR, "risk")
REPORTS_DIR = os.path.join(BASE_OUTPUT_DIR, "reports")


def _next_seq(directory):
    """Return the next 3-digit sequence number (001, 002, ...) based on
    how many files already exist in the given directory."""
    os.makedirs(directory, exist_ok=True)
    existing = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    return f"{len(existing) + 1:03d}"


def get_aws_context(session=None):
    """Retrieve AWS Account ID and Region for reporting context."""
    sess = session or boto3.Session()
    region = sess.region_name or "us-east-1"
    account_id = "UNKNOWN"
    try:
        sts = sess.client('sts')
        account_id = sts.get_caller_identity().get('Account')
    except ClientError:
        pass
    return account_id, region


def adapt_findings_for_remediation(findings):
    """
    Adapter function that bridges fields from our base scanners to the format
    expected by the Remediation Engine (Anish's module).
    """
    adapted = []
    for f in findings:
        af = dict(f)
        af["service"] = f.get("aws_service")
        af["misconfiguration_id"] = f.get("check_id")
        af["misconfiguration"] = f.get("check_name")
        adapted.append(af)
    return adapted


def run_scan(services=None, session=None, skip_scoring=False, auto_remediate=False, dry_run=False):
    """
    Run selected (or all) scanners, score findings, and write timestamped
    JSON and HTML reports to output directories.
    """
    if services is None:
        services = list(SCANNER_MAP.keys())

    all_findings = []
    service_summary = {}

    start_time = time.time()
    account_id, aws_region = get_aws_context(session)

    print("=" * 60)
    print("  AWS Security Posture Assessment Tool")
    print("=" * 60)
    print(f"  Account ID : {account_id}")
    print(f"  Region     : {aws_region}")
    print(f"  Services   : {', '.join(s.upper() for s in services)}")
    print(f"  Scoring    : {'Disabled' if skip_scoring else 'Enabled'}")
    print(f"  Timestamp  : {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print("=" * 60)
    print()

    # ── Phase 1: Run Scanners ────────────────────────────────────────────
    print("Phase 1: Running AWS Security Scanners")
    print("-" * 40)

    for service_key in services:
        if service_key not in SCANNER_MAP:
            print(f"  [WARNING] Unknown service '{service_key}' — skipping.")
            continue

        label, ScannerClass = SCANNER_MAP[service_key]
        try:
            scanner = ScannerClass(session=session)
            findings = scanner.scan()
            all_findings.extend(findings)
            service_summary[label] = len(findings)
            print(f"  ✓ {label} scan complete — {len(findings)} finding(s)\n")
        except Exception as e:
            print(f"  ✗ {label} scan failed — {e}\n")
            service_summary[label] = "ERROR"

    # ── Phase 2: Risk Scoring (Vedansh's Engine) ─────────────────────────
    posture_score = None
    scored_findings = all_findings

    if not skip_scoring and all_findings:
        print("Phase 2: Running Risk Scoring Engine")
        print("-" * 40)

        adapted_findings = enrich_scanner_findings(all_findings)
        scored_findings, posture_score = score_findings(adapted_findings)
        scored_findings.sort(key=lambda f: f.get("risk_score", 0), reverse=True)

        compound_count = sum(1 for f in scored_findings if f.get("compound_risk_applied"))
        print(f"  ✓ Scored {len(scored_findings)} finding(s)")
        print(f"  ✓ Compound risk detected on {compound_count} finding(s)")
        print(f"  ✓ Overall posture score: {posture_score}/100\n")

    elif not all_findings:
        print("  No findings to score — all clear!\n")
        posture_score = 100.0

    scan_duration_seconds = round(time.time() - start_time, 2)
    resources_with_findings = len(set(f.get("resource_arn", f.get("resource_id")) for f in all_findings))

    # ── Generate timestamp and sequence numbers ─────────────────────────
    now = datetime.datetime.now(datetime.timezone.utc)
    ts = now.strftime("%Y-%m-%d_%H-%M-%S")
    scan_date_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Common Metadata ──────────────────────────────────────────────────
    base_metadata = {
        "scan_date": scan_date_iso,
        "account_id": account_id,
        "region_scanned": aws_region,
        "scan_duration_seconds": scan_duration_seconds,
        "scanner_version": "2.0 (Capstone Edition)",
        "module": "AWS Cloud Misconfiguration Detection System",
        "services_scanned": [s.upper() for s in services],
        "total_findings": len(all_findings),
    }

    # ── File 1: Raw scan findings → findings/ folder ─────────────────────
    seq_scan = _next_seq(FINDINGS_DIR)
    scan_filename = f"{seq_scan}_scan_{ts}.json"
    scan_path = os.path.join(FINDINGS_DIR, scan_filename)

    scan_report = {
        "metadata": {
            **base_metadata,
            "scan_number": seq_scan,
            "report_type": "raw_findings",
        },
        "summary": {
            "by_service_finding_count": service_summary,
            "unique_resources_with_findings": resources_with_findings,
            "scan_status": "COMPLETED",
        },
        "findings": all_findings,
    }

    with open(scan_path, "w") as f:
        json.dump(scan_report, f, indent=4)

    # ── File 2: Risk-scored report → risk/ folder ────────────────────────
    risk_path = None
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    risk_report = None

    if not skip_scoring and all_findings:
        seq_risk = _next_seq(RISK_DIR)
        risk_filename = f"{seq_risk}_risk_{ts}.json"
        risk_path = os.path.join(RISK_DIR, risk_filename)

        severity_counts = {
            "critical": sum(1 for f in scored_findings if f.get("contextual_risk_level", f.get("severity")) == "Critical"),
            "high": sum(1 for f in scored_findings if f.get("contextual_risk_level", f.get("severity")) == "High"),
            "medium": sum(1 for f in scored_findings if f.get("contextual_risk_level", f.get("severity")) == "Medium"),
            "low": sum(1 for f in scored_findings if f.get("contextual_risk_level", f.get("severity")) == "Low"),
        }

        risk_report = {
            "metadata": {
                **base_metadata,
                "scan_number": seq_risk,
                "report_type": "risk_scored_findings",
            },
            "summary": {
                "overall_posture_score": posture_score,
                "finding_severity_breakdown": severity_counts,
                "by_service_finding_count": service_summary,
                "unique_resources_with_findings": resources_with_findings,
                "compound_risks_detected": sum(1 for f in scored_findings if f.get("compound_risk_applied")),
                "scan_status": "COMPLETED",
            },
            "findings": scored_findings,
        }

        with open(risk_path, "w") as f:
            json.dump(risk_report, f, indent=4)

    # ── Phase 3: Remediation & HTML Reports (Anish's Engine) ────────────
    html_path = None
    if not skip_scoring and risk_report and all_findings:
        print("Phase 3: Running Remediation Engine & Generating Reports")
        print("-" * 40)
        try:
            remediation_engine = RemediationEngine()
            
            # 1. Map fields for the remediation engine
            mapped_findings = adapt_findings_for_remediation(scored_findings)
            
            # 2. Inject mapped findings into a copy of the risk report
            temp_report = dict(risk_report)
            temp_report["findings"] = mapped_findings
            
            # 3. Process through Anish's module
            final_report = remediation_engine.process_scan_report(temp_report)
            
            # 4. Generate Output Files
            os.makedirs(REPORTS_DIR, exist_ok=True)
            seq_rep = _next_seq(REPORTS_DIR)
            
            json_path = os.path.join(REPORTS_DIR, f"{seq_rep}_final_report_{ts}.json")
            html_path = os.path.join(REPORTS_DIR, f"{seq_rep}_final_report_{ts}.html")
            
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(final_report, f, indent=4)
                
            generate_html_report(final_report, html_path)
            
            matched_count = sum(1 for f in final_report["findings"] if f.get("recommendation_status") == "MATCHED")
            print(f"  ✓ Remediation matched for {matched_count} finding(s)")
            print(f"  ✓ Final JSON generated")
            print(f"  ✓ Final HTML report generated\n")
            
            if auto_remediate:
                run_auto_remediation(final_report["findings"], dry_run=dry_run)
                print()
            
            
        except Exception as e:
            print(f"  ✗ Remediation Engine failed — {e}\n")


    # ── Print summary ────────────────────────────────────────────────────
    print("=" * 60)
    print("  Scan Summary")
    print("=" * 60)
    print(f"    Account ID             : {account_id}")
    print(f"    Duration               : {scan_duration_seconds} seconds")
    print(f"    Resources w/ Findings  : {resources_with_findings}")
    print(f"    Total Findings         : {len(scored_findings)}")
    print()
    if not skip_scoring and all_findings:
        print(f"  Severity breakdown:")
        print(f"    Critical : {severity_counts['critical']}")
        print(f"    High     : {severity_counts['high']}")
        print(f"    Medium   : {severity_counts['medium']}")
        print(f"    Low      : {severity_counts['low']}")
        print()
        print(f"  🛡️  Security Posture Score: {posture_score}/100")
        print()
    print(f"  📄 Saved reports:")
    print(f"    Findings : {scan_path}")
    if risk_path:
        print(f"    Risk     : {risk_path}")
    if html_path:
        print(f"    HTML     : {html_path}")
    print("=" * 60)

    return scan_report, risk_report if risk_path else None


def main():
    parser = argparse.ArgumentParser(
        description="AWS Cloud Misconfiguration Detection System"
    )
    parser.add_argument(
        "--services",
        nargs="+",
        choices=list(SCANNER_MAP.keys()),
        default=None,
        help="Services to scan (default: all). Example: --services iam s3 ec2 lambda",
    )
    parser.add_argument(
        "--skip-scoring",
        action="store_true",
        default=False,
        help="Skip the risk scoring engine and output raw findings only.",
    )
    parser.add_argument(
        "--auto-remediate",
        action="store_true",
        default=False,
        help="Automatically applies fixes to the AWS cloud for supported misconfigurations.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview auto-remediation actions without making any changes to AWS.",
    )
    args = parser.parse_args()

    run_scan(
        services=args.services,
        skip_scoring=args.skip_scoring,
        auto_remediate=args.auto_remediate,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
