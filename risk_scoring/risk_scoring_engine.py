"""
Risk Scoring Engine
Module 2 Owner: Vedansh Raj

Implements Contextual Risk Scoring. 
This engine separates the intrinsic Vulnerability Severity (found by the scanner)
from the Contextual Risk Score (calculated here based on the environment).

Key Features:
    - Base Severity mapped to a baseline risk score.
    - Contextual modifiers: Internet Exposure (+15) and Compound Risks (+15).
    - 0-100 Risk Score scale matching industry standards (like CVSS).
    - Ensures high-severity flaws are never implicitly downgraded without justification.
"""

# ---------------------------------------------------------------------------
# Scoring weight tables (0-100 Scale)
# ---------------------------------------------------------------------------

# Base score derived from the intrinsic severity of the misconfiguration
BASE_SEVERITY_SCORES = {
    "Critical": 85,
    "High": 70,
    "Medium": 40,
    "Low": 15,
}
DEFAULT_BASE_SCORE = 15

# Contextual Risk Modifiers (Additive)
EXPOSURE_BONUS = {
    "public": 15,
    "private": 0,
}
DEFAULT_EXPOSURE = "private"

# Bonus applied when a finding's risk is amplified by a related finding
# in another service (e.g., exposed EC2 + admin IAM policy)
COMPOUND_RISK_BONUS = 15

# Contextual Risk Level Thresholds
CRITICAL_RISK_THRESHOLD = 90
HIGH_RISK_THRESHOLD = 70
MEDIUM_RISK_THRESHOLD = 40
# Below 40 is Low Risk

# ---------------------------------------------------------------------------
# Check-ID → resource_type mapping for scanner output adaptation
# ---------------------------------------------------------------------------

CHECK_ID_SERVICE_MAP = {
    "IAM": "IAM",
    "S3": "S3",
    "EC2": "EC2",
    "LAMBDA": "Lambda",
}

# Scanner check IDs whose findings indicate public exposure
PUBLIC_EXPOSURE_CHECKS = {
    "EC2-01", "EC2-02", "EC2-03", "EC2-06",   # SSH/RDP/all-ports open, public IP
    "EC2-12",                                    # publicly shared snapshots
    "S3-01", "S3-02", "S3-03", "S3-07",         # public ACL, policy, block-off, CORS *
    "LAMBDA-01", "LAMBDA-10",                    # public invoke policy, CORS wildcard
}

# Scanner check IDs that indicate admin-level access grants
ADMIN_GRANT_CHECKS = {
    "IAM-03", "IAM-10",                          # wildcard policies, admin attached broadly
    "LAMBDA-02", "LAMBDA-09",                    # admin role on Lambda, wildcard resource
}


# ---------------------------------------------------------------------------
# Adapter: bridge raw scanner findings → risk scoring input format
# ---------------------------------------------------------------------------

def enrich_scanner_findings(raw_findings):
    """
    Converts raw findings from the scanners into the risk scoring input format.
    Passes through all fields (like resource_arn, recommendation) and adds metadata.
    """
    enriched = []
    for f in raw_findings:
        check_id = f.get("check_id", "")
        prefix = check_id.split("-")[0] if "-" in check_id else ""
        resource_type = CHECK_ID_SERVICE_MAP.get(prefix, "Unknown")

        enriched.append({
            **f,
            "resource_type": resource_type,
            "exposure": "public" if check_id in PUBLIC_EXPOSURE_CHECKS else "private",
            "grants_admin": check_id in ADMIN_GRANT_CHECKS,
        })
    return enriched


# ---------------------------------------------------------------------------
# Cross-service compound risk detection
# ---------------------------------------------------------------------------

def detect_compound_risk(finding, all_findings):
    """
    Checks whether this finding's risk is amplified by a related finding
    in a different AWS service within the same batch.
    """
    if not all_findings:
        return False

    if finding.get("resource_type") not in ("EC2", "S3", "Lambda"):
        return False

    if finding.get("exposure", DEFAULT_EXPOSURE) != "public":
        return False

    for other in all_findings:
        if other is finding:
            continue
        if (
            other.get("resource_type") == "IAM"
            and other.get("severity") in ("Critical", "High")
            and other.get("grants_admin", False)
        ):
            return True

    return False


# ---------------------------------------------------------------------------
# Core scoring functions
# ---------------------------------------------------------------------------

def calculate_risk_score(finding, all_findings=None):
    """
    Calculates the contextual risk score and maps it to a risk level.
    Returns: (risk_score, contextual_risk_level, compound_risk_applied)
    """
    original_severity = finding.get("severity", "Low")
    base_score = BASE_SEVERITY_SCORES.get(original_severity, DEFAULT_BASE_SCORE)

    exposure = finding.get("exposure", DEFAULT_EXPOSURE)
    exposure_score = EXPOSURE_BONUS.get(exposure, 0)

    # Cross-service compound bonus
    compound_risk_applied = detect_compound_risk(finding, all_findings)
    compound_bonus = COMPOUND_RISK_BONUS if compound_risk_applied else 0

    total_score = base_score + exposure_score + compound_bonus
    
    # Cap score at 100
    total_score = min(total_score, 100)

    # Map numeric score to Contextual Risk Level
    if total_score >= CRITICAL_RISK_THRESHOLD:
        label = "Critical"
    elif total_score >= HIGH_RISK_THRESHOLD:
        label = "High"
    elif total_score >= MEDIUM_RISK_THRESHOLD:
        label = "Medium"
    else:
        label = "Low"

    return total_score, label, compound_risk_applied


def calculate_posture_score(scored_findings):
    """
    Overall posture score representing the environment's security health (0-100%).
    A perfectly secure environment is 100.
    Uses an exponential decay model so the score approaches 0 asymptotically
    instead of dropping instantly to zero on large environments.
    """
    posture_score = 100.0
    
    # Decay factors per finding based on contextual risk level.
    # A Critical finding reduces the current score by 15%, High by 8%, etc.
    decay_map = {
        "Critical": 0.85,
        "High": 0.92,
        "Medium": 0.97,
        "Low": 0.99
    }
    
    for f in scored_findings:
        level = f.get("contextual_risk_level", "Low")
        factor = decay_map.get(level, 0.99)
        posture_score *= factor

    return max(round(posture_score, 1), 0.0)


def score_findings(findings):
    """
    Wrapper used by the reporting module: scores every finding
    and returns an enriched list plus the overall posture score.
    """
    enriched = []
    for f in findings:
        score, label, compound = calculate_risk_score(f, all_findings=findings)
        
        # We explicitly preserve the original scanner severity
        # and add the new contextual risk fields.
        enriched.append({
            **f,
            "original_severity": f.get("severity"),
            "risk_score": score,
            "contextual_risk_level": label,
            "compound_risk_applied": compound,
        })
        
        # Optionally, we can remove the old raw 'severity' key to avoid confusion, 
        # or leave it. We will leave it since it represents Vulnerability Severity,
        # but the orchestrator relies on 'contextual_risk_level' for counts.

    posture_score = calculate_posture_score(enriched)
    return enriched, posture_score


if __name__ == "__main__":
    sample_findings = [
        {"check_id": "S3-01", "severity": "Critical"},
        {"check_id": "IAM-10", "severity": "High"},
        {"check_id": "EC2-07", "severity": "Medium"},
    ]
    enriched = enrich_scanner_findings(sample_findings)
    scored, posture = score_findings(enriched)

    for f in scored:
        print(f"{f['check_id']} | Base Sev: {f['original_severity']} -> Contextual Risk: {f['contextual_risk_level']} (Score: {f['risk_score']})")
    print(f"Posture: {posture}")
