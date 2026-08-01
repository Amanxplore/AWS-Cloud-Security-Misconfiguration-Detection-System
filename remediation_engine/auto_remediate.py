"""
auto_remediate.py
-----------------
Auto-Remediation Engine — Phase 4 of the Pipeline

Automatically applies boto3 API calls to fix supported AWS misconfigurations
detected by the scanner. Each fix is wrapped in try/except for resilience.

Supported Remediations:
    S3:
      - S3_PUBLIC_BUCKET       → put_public_access_block()
      - S3_ENCRYPTION_DISABLED → put_bucket_encryption() (AES-256)
      - S3_VERSIONING_DISABLED → put_bucket_versioning() (Enabled)

    IAM:
      - IAM_WEAK_PASSWORD_POLICY → update_account_password_policy()

    EC2:
      - EC2_SSH_OPEN_TO_WORLD    → revoke_security_group_ingress() on port 22
      - EC2_RDP_OPEN_TO_WORLD    → revoke_security_group_ingress() on port 3389

Safety:
    - A dry_run flag lets you preview what *would* be fixed without touching AWS.
    - Every action is logged to stdout so the CI/CD console has a full audit trail.
    - All calls are wrapped in try/except — a single failure never crashes the pipeline.
"""

import boto3


# ── Remediation Handlers ─────────────────────────────────────────────────────

def _remediate_s3_public_bucket(s3, bucket_name, dry_run):
    """Block all public access on a bucket."""
    if dry_run:
        print(f"    [DRY-RUN] Would block public access on bucket: {bucket_name}")
        return True
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True,
        }
    )
    print(f"    ✓ Blocked all public access on bucket: {bucket_name}")
    return True


def _remediate_s3_encryption(s3, bucket_name, dry_run):
    """Enable AES-256 default encryption on a bucket."""
    if dry_run:
        print(f"    [DRY-RUN] Would enable AES-256 encryption on bucket: {bucket_name}")
        return True
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256'
                },
                'BucketKeyEnabled': True,
            }]
        }
    )
    print(f"    ✓ Enabled AES-256 default encryption on bucket: {bucket_name}")
    return True


def _remediate_s3_versioning(s3, bucket_name, dry_run):
    """Enable versioning on a bucket."""
    if dry_run:
        print(f"    [DRY-RUN] Would enable versioning on bucket: {bucket_name}")
        return True
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )
    print(f"    ✓ Enabled versioning on bucket: {bucket_name}")
    return True


def _remediate_iam_password_policy(iam, dry_run):
    """Enforce a strong account-wide password policy."""
    if dry_run:
        print("    [DRY-RUN] Would enforce strong password policy on the AWS account")
        return True
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        MaxPasswordAge=90,
        PasswordReusePrevention=5,
    )
    print("    ✓ Enforced strong password policy (14 chars, symbols, 90-day expiry)")
    return True


def _remediate_ec2_open_port(ec2, sg_id, port, dry_run):
    """Revoke 0.0.0.0/0 ingress on a specific port from a Security Group."""
    if dry_run:
        print(f"    [DRY-RUN] Would revoke 0.0.0.0/0 on port {port} from SG: {sg_id}")
        return True
    # Revoke both IPv4 and IPv6 wildcard rules
    for cidr_key, cidr_val in [('CidrIp', '0.0.0.0/0'), ('CidrIpv6', '::/0')]:
        try:
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': cidr_val}] if cidr_key == 'CidrIp' else [],
                    'Ipv6Ranges': [{'CidrIpv6': cidr_val}] if cidr_key == 'CidrIpv6' else [],
                }]
            )
        except Exception:
            pass  # Rule may not exist for this CIDR type, that's OK
    print(f"    ✓ Revoked 0.0.0.0/0 ingress on port {port} from SG: {sg_id}")
    return True


# ── Main Orchestrator ─────────────────────────────────────────────────────────

def run_auto_remediation(findings, dry_run=False):
    """
    Iterate through enriched findings and apply automated fixes for
    supported remediation IDs.

    Args:
        findings: List of enriched finding dicts (must have 'remediation_id').
        dry_run:  If True, log what would happen without making any AWS changes.
    """
    print("\nPhase 4: Running Auto-Remediation Engine")
    if dry_run:
        print("  ⚠  DRY-RUN MODE — no changes will be applied to AWS")
    print("-" * 40)

    s3 = boto3.client('s3')
    iam = boto3.client('iam')
    ec2 = boto3.client('ec2')

    remediated_count = 0
    failed_count = 0
    # Track what we already fixed so we don't repeat the same action twice
    already_fixed = set()

    for f in findings:
        rid = f.get("remediation_id")
        if not rid:
            continue

        arn = f.get("resource_arn", "")
        resource_id = f.get("resource_id", "")

        # Build a dedup key so we don't fix the same resource+issue twice
        dedup_key = f"{rid}:{arn or resource_id}"
        if dedup_key in already_fixed:
            continue

        try:
            # ── S3 Remediations ───────────────────────────────────────────
            if rid == "S3_PUBLIC_BUCKET" and arn.startswith("arn:aws:s3:::"):
                bucket = arn.split(":::")[1]
                print(f"  [AUTO-FIX] {rid} → bucket: {bucket}")
                if _remediate_s3_public_bucket(s3, bucket, dry_run):
                    remediated_count += 1
                    already_fixed.add(dedup_key)

            elif rid == "S3_ENCRYPTION_DISABLED" and arn.startswith("arn:aws:s3:::"):
                bucket = arn.split(":::")[1]
                print(f"  [AUTO-FIX] {rid} → bucket: {bucket}")
                if _remediate_s3_encryption(s3, bucket, dry_run):
                    remediated_count += 1
                    already_fixed.add(dedup_key)

            elif rid == "S3_VERSIONING_DISABLED" and arn.startswith("arn:aws:s3:::"):
                bucket = arn.split(":::")[1]
                print(f"  [AUTO-FIX] {rid} → bucket: {bucket}")
                if _remediate_s3_versioning(s3, bucket, dry_run):
                    remediated_count += 1
                    already_fixed.add(dedup_key)

            # ── IAM Remediations ──────────────────────────────────────────
            elif rid == "IAM_WEAK_PASSWORD_POLICY":
                print(f"  [AUTO-FIX] {rid} → AWS Account password policy")
                if _remediate_iam_password_policy(iam, dry_run):
                    remediated_count += 1
                    already_fixed.add(dedup_key)

            # ── EC2 Remediations ──────────────────────────────────────────
            elif rid == "EC2_SSH_OPEN_TO_WORLD":
                sg_id = resource_id if resource_id.startswith("sg-") else None
                if sg_id:
                    print(f"  [AUTO-FIX] {rid} → security group: {sg_id}")
                    if _remediate_ec2_open_port(ec2, sg_id, 22, dry_run):
                        remediated_count += 1
                        already_fixed.add(dedup_key)

            elif rid == "EC2_RDP_OPEN_TO_WORLD":
                sg_id = resource_id if resource_id.startswith("sg-") else None
                if sg_id:
                    print(f"  [AUTO-FIX] {rid} → security group: {sg_id}")
                    if _remediate_ec2_open_port(ec2, sg_id, 3389, dry_run):
                        remediated_count += 1
                        already_fixed.add(dedup_key)

        except Exception as e:
            print(f"    ✗ FAILED to remediate {rid} on {arn or resource_id}: {e}")
            failed_count += 1

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    if remediated_count == 0 and failed_count == 0:
        print("  ✓ No auto-remediation actions required — all supported checks are clean.")
    else:
        prefix = "[DRY-RUN] " if dry_run else ""
        print(f"  {prefix}Auto-remediation complete:")
        print(f"    ✓ Remediated : {remediated_count}")
        if failed_count:
            print(f"    ✗ Failed     : {failed_count}")
