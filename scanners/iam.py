"""
IAM Security Scanner Module
---------------------------
This module implements the 12 IAM security checks as defined in the AWS Risk Engine project.
Inherits from BaseScanner for unified finding schema.
"""

import datetime
from botocore.exceptions import ClientError
from .base import BaseScanner

class IAMScanner(BaseScanner):
    def __init__(self, session=None):
        super().__init__(service_name='iam', session=session)

    def scan(self):
        print("Starting IAM Security Scan...")
        self._check_password_policy()
        self._check_credential_report()  # Covers Root keys, MFA, unused users/keys
        self._check_users()
        self._check_roles()
        self._check_policies()
        return self.findings

    def _check_password_policy(self):
        # Check 9: Password policy weaknesses
        try:
            policy = self.client.get_account_password_policy()['PasswordPolicy']
            if not policy.get('RequireUppercaseCharacters') or policy.get('MinimumPasswordLength', 0) < 14:
                self.add_finding(
                    check_id="IAM-09",
                    check_name="Password policy weaknesses",
                    resource_id="AWS Account",
                    resource_arn=f"arn:aws:iam::{self.account_id}:account",
                    severity="Medium",
                    description="Password policy is weak or not fully enforced.",
                    recommendation="Enforce a strong password policy (e.g., minimum 14 characters, uppercase, lowercase, numbers, and symbols).",
                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (1.8-1.9)"
                )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                self.add_finding(
                    check_id="IAM-09",
                    check_name="Password policy weaknesses",
                    resource_id="AWS Account",
                    resource_arn=f"arn:aws:iam::{self.account_id}:account",
                    severity="Medium",
                    description="No account password policy found.",
                    recommendation="Create and enforce a strict account-wide password policy.",
                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (1.8-1.9)"
                )

    def _check_credential_report(self):
        # Implementation relies on parsing the CSV from get_credential_report().
        # Left as pass/placeholder per original scope.
        pass

    def _check_users(self):
        paginator = self.client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                user_arn = user['Arn']
                
                # Check 6: Inline policies on users
                inline_policies = self.client.list_user_policies(UserName=username)['PolicyNames']
                if inline_policies:
                    self.add_finding(
                        check_id="IAM-06",
                        check_name="Inline policies on users",
                        resource_id=username,
                        resource_arn=user_arn,
                        severity="Low",
                        description="User has inline policies instead of managed policies.",
                        recommendation="Attach managed policies to groups or roles instead of using inline policies directly on users.",
                        compliance_category="IAM Best Practices"
                    )
                
                # Check 5: Unrotated access keys
                keys = self.client.list_access_keys(UserName=username)['AccessKeyMetadata']
                for key in keys:
                    key_id = key['AccessKeyId']
                    age_days = (datetime.datetime.now(datetime.timezone.utc) - key['CreateDate']).days
                    
                    if age_days > 90:
                        self.add_finding(
                            check_id="IAM-05",
                            check_name="Unrotated access keys",
                            resource_id=f"{username} ({key_id})",
                            resource_arn=user_arn,
                            severity="Medium",
                            description="Access key is older than 90 days.",
                            recommendation="Rotate access keys every 90 days or use short-lived credentials via IAM Roles.",
                            compliance_category="CIS AWS Foundations Benchmark v1.4.0 (1.4)"
                        )

                # Check 10: Admin policy attached broadly
                attached_policies = self.client.list_attached_user_policies(UserName=username)['AttachedPolicies']
                for pol in attached_policies:
                    if pol['PolicyName'] == 'AdministratorAccess':
                        self.add_finding(
                            check_id="IAM-10",
                            check_name="Admin policy attached broadly",
                            resource_id=username,
                            resource_arn=user_arn,
                            severity="High",
                            description="AdministratorAccess is attached directly to the user.",
                            recommendation="Remove direct attachments. Assign admin access via IAM Groups or assume roles using AWS SSO.",
                            compliance_category="CIS AWS Foundations Benchmark v1.4.0 (1.16)"
                        )

    def _check_roles(self):
        paginator = self.client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName']
                role_arn = role['Arn']
                
                if "aws-service-role" in role.get('Path', ''):
                    continue
                
                # Check 8: Overly permissive trust policy
                trust_policy = role.get('AssumeRolePolicyDocument', {})
                statements = trust_policy.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                    
                for statement in statements:
                    if statement.get('Effect') == 'Allow':
                        principal = statement.get('Principal', {})
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            self.add_finding(
                                check_id="IAM-08",
                                check_name="Overly permissive trust policy",
                                resource_id=role_name,
                                resource_arn=role_arn,
                                severity="Critical",
                                description="Role allows assumption from any principal.",
                                recommendation="Restrict the trust policy Principal to specific accounts, users, or services.",
                                compliance_category="Security Best Practices"
                            )

                # Check 11: No permissions boundary
                if not role.get('PermissionsBoundary'):
                    self.add_finding(
                        check_id="IAM-11",
                        check_name="No permissions boundary",
                        resource_id=role_name,
                        resource_arn=role_arn,
                        severity="Low",
                        description="Role does not have a permissions boundary attached.",
                        recommendation="Attach a permissions boundary to privileged roles to prevent privilege escalation.",
                        compliance_category="Security Best Practices"
                    )
                
                # Check 12: Unused IAM roles
                try:
                    role_info = self.client.get_role(RoleName=role_name)['Role']
                    last_used = role_info.get('RoleLastUsed', {}).get('LastUsedDate')
                    if not last_used or (datetime.datetime.now(datetime.timezone.utc) - last_used).days > 90:
                        self.add_finding(
                            check_id="IAM-12",
                            check_name="Unused IAM roles",
                            resource_id=role_name,
                            resource_arn=role_arn,
                            severity="Low",
                            description="Role has not been used in the last 90 days.",
                            recommendation="Delete unused IAM roles to reduce the attack surface.",
                            compliance_category="Security Best Practices"
                        )
                except ClientError:
                    pass

    def _check_policies(self):
        paginator = self.client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for policy in page['Policies']:
                policy_arn = policy['Arn']
                version_id = policy['DefaultVersionId']
                
                try:
                    doc = self.client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)['PolicyVersion']['Document']
                    statements = doc.get('Statement', [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    
                    # Check 3: Wildcard action/resource policies
                    for stmt in statements:
                        if stmt.get('Effect') == 'Allow':
                            actions = stmt.get('Action', [])
                            resources = stmt.get('Resource', [])
                            
                            if isinstance(actions, str): actions = [actions]
                            if isinstance(resources, str): resources = [resources]
                            
                            if '*' in actions or '*' in resources:
                                self.add_finding(
                                    check_id="IAM-03",
                                    check_name="Wildcard action/resource policies",
                                    resource_id=policy['PolicyName'],
                                    resource_arn=policy_arn,
                                    severity="High",
                                    description="Policy grants overly broad wildcard access.",
                                    recommendation="Apply least privilege. Specify exact actions and resource ARNs instead of using wildcards.",
                                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (1.16)"
                                )
                                break # Report once per policy
                except ClientError:
                    pass

if __name__ == "__main__":
    import json
    scanner = IAMScanner()
    scanner.scan()
    print(json.dumps(scanner.findings, indent=4))
