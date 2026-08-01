"""
S3 Security Scanner Module
--------------------------
This module implements the 12 S3 security checks as defined in the AWS Risk Engine project.
Inherits from BaseScanner for unified finding schema.
"""

from botocore.exceptions import ClientError
import json
from .base import BaseScanner

class S3Scanner(BaseScanner):
    def __init__(self, session=None):
        super().__init__(service_name='s3', session=session)
        # S3 buckets are global but usually have a location, we use global arn format

    def scan(self):
        print("Starting S3 Security Scan...")
        response = self.client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            
            self._check_public_access_block(bucket_name, bucket_arn)
            self._check_acl(bucket_name, bucket_arn)
            self._check_policy(bucket_name, bucket_arn)
            self._check_encryption(bucket_name, bucket_arn)
            self._check_versioning(bucket_name, bucket_arn)
            self._check_logging(bucket_name, bucket_arn)
            self._check_cors(bucket_name, bucket_arn)
            self._check_lifecycle(bucket_name, bucket_arn)
            self._check_empty_bucket(bucket_name, bucket_arn)

        return self.findings

    def _check_public_access_block(self, bucket_name, bucket_arn):
        # Check 3: Block Public Access disabled
        try:
            pab = self.client.get_public_access_block(Bucket=bucket_name)
            config = pab['PublicAccessBlockConfiguration']
            if not all([config.get('BlockPublicAcls'), config.get('IgnorePublicAcls'), 
                        config.get('BlockPublicPolicy'), config.get('RestrictPublicBuckets')]):
                self.add_finding(
                    check_id="S3-03", 
                    check_name="Block Public Access disabled", 
                    resource_id=bucket_name, 
                    resource_arn=bucket_arn,
                    severity="High", 
                    description="S3 Block Public Access is not fully enabled.",
                    recommendation="Enable all four S3 Block Public Access settings at the bucket or account level.",
                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (2.1.5)"
                )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                self.add_finding(
                    check_id="S3-03", 
                    check_name="Block Public Access disabled", 
                    resource_id=bucket_name, 
                    resource_arn=bucket_arn,
                    severity="High", 
                    description="No S3 Block Public Access configuration exists.",
                    recommendation="Enable S3 Block Public Access to prevent accidental exposure.",
                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (2.1.5)"
                )

    def _check_acl(self, bucket_name, bucket_arn):
        # Check 1: Public bucket ACL
        try:
            acl = self.client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('Type') == 'Group' and ('AllUsers' in grantee.get('URI', '') or 'AuthenticatedUsers' in grantee.get('URI', '')):
                    self.add_finding(
                        check_id="S3-01", 
                        check_name="Public bucket ACL", 
                        resource_id=bucket_name, 
                        resource_arn=bucket_arn,
                        severity="Critical", 
                        description="Bucket ACL allows public read or write access.",
                        recommendation="Remove public ACL grants and rely on IAM or Bucket Policies for access control.",
                        compliance_category="Security Best Practices"
                    )
                    break
        except ClientError:
            pass

    def _check_policy(self, bucket_name, bucket_arn):
        # Check 2: Public bucket policy
        # Check 10: Cross-account access
        # Check 11: Unencrypted object uploads allowed
        try:
            policy_str = self.client.get_bucket_policy(Bucket=bucket_name)['Policy']
            policy = json.loads(policy_str)
            
            secure_transport_enforced = False
            for statement in policy.get('Statement', []):
                
                # S3-02 Public bucket policy
                if statement.get('Effect') == 'Allow' and statement.get('Principal') == '*':
                    if not statement.get('Condition'):
                        self.add_finding(
                            check_id="S3-02", 
                            check_name="Public bucket policy", 
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            severity="Critical", 
                            description="Bucket policy allows public access without conditions.",
                            recommendation="Restrict bucket policy principals or add explicit conditions (e.g., specific IP ranges).",
                            compliance_category="CIS AWS Foundations Benchmark v1.4.0 (2.1.5)"
                        )
                
                # S3-10 Cross-account access (simplified check for external AWS accounts)
                if statement.get('Effect') == 'Allow' and isinstance(statement.get('Principal'), dict):
                    aws_principals = statement['Principal'].get('AWS', [])
                    if isinstance(aws_principals, str): aws_principals = [aws_principals]
                    for prin in aws_principals:
                        if 'arn:aws:iam::' in prin and self.account_id not in prin:
                            self.add_finding(
                                check_id="S3-10", 
                                check_name="Cross-account access", 
                                resource_id=bucket_name, 
                                resource_arn=bucket_arn,
                                severity="High", 
                                description="Bucket policy grants access to specific external accounts. Requires review.",
                                recommendation="Audit cross-account access and ensure only trusted external accounts have access.",
                                compliance_category="Security Best Practices"
                            )
                            break

                # S3-11 Unencrypted object uploads allowed
                if statement.get('Effect') == 'Deny':
                    condition = statement.get('Condition', {})
                    if condition.get('Bool', {}).get('aws:SecureTransport') == 'false':
                        secure_transport_enforced = True
            
            if not secure_transport_enforced:
                self.add_finding(
                    check_id="S3-11", 
                    check_name="Unencrypted object uploads allowed", 
                    resource_id=bucket_name,
                    resource_arn=bucket_arn,
                    severity="Medium", 
                    description="Bucket does not explicitly deny non-HTTPS uploads.",
                    recommendation="Add a bucket policy denying s3:PutObject if aws:SecureTransport is false.",
                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (2.1.2)"
                )
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                self.add_finding(
                    check_id="S3-11", 
                    check_name="Unencrypted object uploads allowed", 
                    resource_id=bucket_name, 
                    resource_arn=bucket_arn,
                    severity="Medium", 
                    description="No bucket policy enforcing HTTPS.",
                    recommendation="Create a bucket policy that denies requests without aws:SecureTransport.",
                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (2.1.2)"
                )

    def _check_encryption(self, bucket_name, bucket_arn):
        # Check 4: No server-side encryption
        try:
            self.client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                self.add_finding(
                    check_id="S3-04", 
                    check_name="No server-side encryption", 
                    resource_id=bucket_name, 
                    resource_arn=bucket_arn,
                    severity="High", 
                    description="Bucket does not have default encryption enabled.",
                    recommendation="Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket.",
                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (2.1.1)"
                )

    def _check_versioning(self, bucket_name, bucket_arn):
        # Check 5: Versioning disabled
        # Check 9: MFA delete disabled
        try:
            versioning = self.client.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                self.add_finding(
                    check_id="S3-05", 
                    check_name="Versioning disabled", 
                    resource_id=bucket_name, 
                    resource_arn=bucket_arn,
                    severity="Medium", 
                    description="Bucket versioning is not enabled.",
                    recommendation="Enable versioning to protect against accidental overwrites or deletions.",
                    compliance_category="Security Best Practices"
                )
            elif versioning.get('MFADelete') != 'Enabled':
                self.add_finding(
                    check_id="S3-09", 
                    check_name="MFA delete disabled", 
                    resource_id=bucket_name, 
                    resource_arn=bucket_arn,
                    severity="Medium", 
                    description="MFA Delete is not enabled on a versioned bucket.",
                    recommendation="Enable MFA Delete to prevent unauthorized permanent deletions of versions.",
                    compliance_category="Security Best Practices"
                )
        except ClientError:
            pass

    def _check_logging(self, bucket_name, bucket_arn):
        # Check 6: No logging enabled
        try:
            logging = self.client.get_bucket_logging(Bucket=bucket_name)
            if not logging.get('LoggingEnabled'):
                self.add_finding(
                    check_id="S3-06", 
                    check_name="No logging enabled", 
                    resource_id=bucket_name, 
                    resource_arn=bucket_arn,
                    severity="Medium", 
                    description="Server access logging is not configured.",
                    recommendation="Enable S3 server access logging or CloudTrail data events to track bucket activity.",
                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (3.6)"
                )
        except ClientError:
            pass

    def _check_cors(self, bucket_name, bucket_arn):
        # Check 7: Public access via CORS
        try:
            cors = self.client.get_bucket_cors(Bucket=bucket_name)
            for rule in cors.get('CORSRules', []):
                if '*' in rule.get('AllowedOrigins', []):
                    self.add_finding(
                        check_id="S3-07", 
                        check_name="Public access via CORS", 
                        resource_id=bucket_name, 
                        resource_arn=bucket_arn,
                        severity="Medium", 
                        description="CORS configuration allows requests from any origin.",
                        recommendation="Restrict CORS AllowedOrigins to specific, trusted domains.",
                        compliance_category="Security Best Practices"
                    )
                    break
        except ClientError:
            pass

    def _check_lifecycle(self, bucket_name, bucket_arn):
        # Check 8: No lifecycle policy
        try:
            self.client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                self.add_finding(
                    check_id="S3-08", 
                    check_name="No lifecycle policy", 
                    resource_id=bucket_name, 
                    resource_arn=bucket_arn,
                    severity="Low", 
                    description="Bucket lacks a lifecycle policy for managing old objects.",
                    recommendation="Implement a lifecycle policy to transition older objects to cheaper storage or expire them.",
                    compliance_category="Cost Optimization / Best Practices"
                )

    def _check_empty_bucket(self, bucket_name, bucket_arn):
        # Check 12: Unused/empty buckets
        try:
            response = self.client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            if 'Contents' not in response:
                self.add_finding(
                    check_id="S3-12", 
                    check_name="Unused/empty buckets", 
                    resource_id=bucket_name, 
                    resource_arn=bucket_arn,
                    severity="Low", 
                    description="Bucket appears to be empty and unused.",
                    recommendation="Delete unused/empty buckets to maintain a clean environment.",
                    compliance_category="Security Best Practices"
                )
        except ClientError:
            pass

if __name__ == "__main__":
    import json
    scanner = S3Scanner()
    scanner.scan()
    print(json.dumps(scanner.findings, indent=4))
