"""
engine.py
---------
Remediation Recommendation Engine
Deliverable 3 (Member 3) - Week 2

Purpose
-------
Takes misconfiguration "findings" (as produced by the AWS Scanner module,
Member 1) and enriches each one with a recommendation, severity, and
step-by-step remediation guidance, using the knowledge base in
`remediation_mapping.json`.

Integration contract (for Member 1 / Member 2 / Member 4)
----------------------------------------------------------
Input finding (minimum required fields):
    {
        "id": "F001",                      # optional, passed through unchanged
        "service": "S3",                   # required - "IAM" | "S3" | "EC2"
        "resource": "company-backup-bucket",# optional, passed through unchanged
        "misconfiguration": "Public bucket",# required - free text OR...
        "misconfiguration_id": "S3_PUBLIC_BUCKET",  # optional - preferred stable id
        "severity": "Critical",            # optional, overridden by KB if absent
        "risk_score": 95,                  # optional, passed through unchanged
        "status": "Open"                   # optional, passed through unchanged
    }

Matching priority:
    1. `misconfiguration_id` exact match against the knowledge base id (best - use this
       going forward if the scanner can emit it).
    2. `service` + `misconfiguration` text match (case/whitespace-insensitive,
       checked against both the canonical text and its aliases).
    3. No match -> finding is returned with recommendation_status = "NOT_FOUND"
       and a generic manual-review note, instead of crashing. This keeps the
       pipeline resilient while the scanner (Member 1) is still in development.

Output finding (adds these fields to the input, does not remove any):
    {
        ... all original fields ...,
        "severity": "Critical",              # filled in from KB if not provided
        "recommendation": "...",
        "remediation_steps": ["...", "..."],
        "remediation_id": "S3_PUBLIC_BUCKET",
        "recommendation_status": "MATCHED"   # or "NOT_FOUND"
    }

This module has no external dependencies (stdlib only) so it can be dropped
into any teammate's environment without extra installs.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_MAPPING_PATH = Path(__file__).parent / "remediation_mapping.json"


def _normalize(text: str) -> str:
    """Lowercase and collapse whitespace so text matching is forgiving of
    minor formatting differences between what the scanner emits and what's
    in the knowledge base."""
    return re.sub(r"\s+", " ", text.strip().lower())


class RemediationEngine:
    """Loads the remediation knowledge base and generates recommendations
    for individual findings or full scan reports."""

    def __init__(self, mapping_path: Optional[str] = None):
        self.mapping_path = Path(mapping_path) if mapping_path else DEFAULT_MAPPING_PATH
        self._by_id: Dict[str, Dict[str, Any]] = {}
        self._by_service_text: Dict[str, Dict[str, Any]] = {}
        self._load_mapping()

    # ------------------------------------------------------------------ #
    # Setup
    # ------------------------------------------------------------------ #
    def _load_mapping(self) -> None:
        with open(self.mapping_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for entry in data.get("mappings", []):
            self._by_id[entry["id"]] = entry

            service_key = _normalize(entry["service"])
            texts = [entry["misconfiguration"]] + entry.get("aliases", [])
            for text in texts:
                key = (service_key, _normalize(text))
                self._by_service_text[key] = entry

    def reload(self) -> None:
        """Re-read the mapping file from disk (useful if it's edited at runtime)."""
        self._by_id.clear()
        self._by_service_text.clear()
        self._load_mapping()

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #
    def _lookup(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # 1. Preferred: stable id match
        mid = finding.get("misconfiguration_id")
        if mid and mid in self._by_id:
            return self._by_id[mid]

        # 2. Fallback: service + free-text match
        service = finding.get("service", "")
        misconfig_text = finding.get("misconfiguration", "")
        key = (_normalize(service), _normalize(misconfig_text))
        if key in self._by_service_text:
            return self._by_service_text[key]

        return None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def get_recommendation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Return a NEW dict: the original finding enriched with a
        recommendation. Does not mutate the input."""
        enriched = dict(finding)  # shallow copy, preserves all original fields
        match = self._lookup(finding)

        if match is None:
            enriched.setdefault("severity", finding.get("severity", "Unknown"))
            enriched["recommendation"] = (
                "No automated recommendation found for this misconfiguration. "
                "Flag for manual security review."
            )
            enriched["remediation_steps"] = []
            enriched["remediation_id"] = None
            enriched["recommendation_status"] = "NOT_FOUND"
            return enriched

        enriched["severity"] = finding.get("severity") or match["severity"]
        enriched["recommendation"] = match["recommendation"]
        enriched["remediation_steps"] = match["remediation_steps"]
        enriched["remediation_id"] = match["id"]
        enriched["recommendation_status"] = "MATCHED"
        return enriched

    def process_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich a list of findings. This is the shape Member 1's scanner
        is expected to emit (a flat list of finding dicts)."""
        return [self.get_recommendation(f) for f in findings]

    def process_scan_report(self, scan_report: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a full scan report matching the Week 1 JSON schema, i.e.
        {"scan_information": {...}, "summary": {...}, "findings": [...]}.
        Returns a new report dict with findings replaced by enriched ones;
        scan_information and summary are passed through unchanged."""
        report = dict(scan_report)
        report["findings"] = self.process_findings(scan_report.get("findings", []))
        return report

    # ------------------------------------------------------------------ #
    # Introspection helpers (handy for Member 2 / Member 4)
    # ------------------------------------------------------------------ #
    def known_ids(self) -> List[str]:
        return sorted(self._by_id.keys())

    def get_by_id(self, remediation_id: str) -> Optional[Dict[str, Any]]:
        return self._by_id.get(remediation_id)


# ---------------------------------------------------------------------- #
# CLI usage: python engine.py input_findings.json output_report.json
# ---------------------------------------------------------------------- #
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python engine.py <input_scan_report.json> <output_report.json>")
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]

    engine = RemediationEngine()

    with open(input_path, "r", encoding="utf-8") as f:
        scan_report = json.load(f)

    enriched_report = engine.process_scan_report(scan_report)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(enriched_report, f, indent=2)

    print(f"Processed {len(enriched_report.get('findings', []))} findings.")
    print(f"Output written to {output_path}")
