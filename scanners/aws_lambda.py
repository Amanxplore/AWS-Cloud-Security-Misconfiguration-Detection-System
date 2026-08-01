"""
Lambda Security Scanner Module
-------------------------------
This module implements the 15 Lambda security checks as defined in the AWS Risk Engine project.
Inherits from BaseScanner for unified finding schema.
"""

import datetime
import json
from botocore.exceptions import ClientError
from .base import BaseScanner


# Runtimes that have reached end-of-life or are deprecated by AWS
DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
    "ruby2.5", "ruby2.7",
    "java8",
    "go1.x",
}

# Keywords that suggest sensitive data when found in environment variable names
SENSITIVE_ENV_KEYWORDS = [
    "PASSWORD", "SECRET", "API_KEY", "APIKEY", "TOKEN",
    "PRIVATE_KEY", "ACCESS_KEY", "CREDENTIAL", "DB_PASS",
]


class LambdaScanner(BaseScanner):
    def __init__(self, session=None):
        super().__init__(service_name='lambda', session=session)
        # We need IAM client for lambda role checks
        self.iam = self.session.client('iam')

    def scan(self):
        print("Starting Lambda Security Scan...")
        functions = self._list_all_functions()

        for func in functions:
            func_name = func['FunctionName']
            func_arn = func['FunctionArn']

            self._check_public_access(func_name, func_arn)
            self._check_execution_role(func_name, func_arn, func.get('Role', ''))
            self._check_runtime(func_name, func_arn, func.get('Runtime', ''))
            self._check_vpc(func_name, func_arn, func.get('VpcConfig'))
            self._check_env_secrets(func_name, func_arn, func.get('Environment', {}))
            self._check_timeout(func_name, func_arn, func.get('Timeout', 3))
            self._check_memory(func_name, func_arn, func.get('MemorySize', 128))
            self._check_dlq(func_name, func_arn, func.get('DeadLetterConfig'))
            self._check_role_wildcard_resource(func_name, func_arn, func.get('Role', ''))
            self._check_function_url_cors(func_name, func_arn)
            self._check_tracing(func_name, func_arn, func.get('TracingConfig', {}))
            self._check_staleness(func_name, func_arn, func.get('LastModified', ''))
            self._check_code_signing(func_name, func_arn)
            self._check_reserved_concurrency(func_name, func_arn)
            self._check_env_kms(func_name, func_arn, func.get('KMSKeyArn'))

        return self.findings

    def _list_all_functions(self):
        functions = []
        try:
            paginator = self.client.get_paginator('list_functions')
            for page in paginator.paginate():
                functions.extend(page.get('Functions', []))
        except ClientError as e:
            print(f"Error listing Lambda functions: {e}")
        return functions

    def _check_public_access(self, func_name, func_arn):
        try:
            policy_str = self.client.get_policy(FunctionName=func_name)['Policy']
            policy = json.loads(policy_str)

            for statement in policy.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                        self.add_finding(
                            check_id="LAMBDA-01", 
                            check_name="Public access policy", 
                            resource_id=func_name, 
                            resource_arn=func_arn,
                            severity="Critical",
                            description="Function resource-based policy allows invocation from any principal (*).",
                            recommendation="Restrict lambda invocation to specific services, accounts, or VPC endpoints.",
                            compliance_category="Security Best Practices"
                        )
                        return
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                print(f"Error checking policy for {func_name}: {e}")

    def _check_execution_role(self, func_name, func_arn, role_arn):
        if not role_arn:
            return
        role_name = role_arn.split('/')[-1]
        try:
            attached = self.iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            broad_policies = {'AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess'}
            for pol in attached:
                if pol['PolicyName'] in broad_policies:
                    self.add_finding(
                        check_id="LAMBDA-02", 
                        check_name="Overly permissive execution role", 
                        resource_id=func_name, 
                        resource_arn=func_arn,
                        severity="High",
                        description=f"Execution role '{role_name}' has '{pol['PolicyName']}' attached.",
                        recommendation="Use AWS managed policies specific to Lambda (like AWSLambdaBasicExecutionRole) and add least-privilege inline policies for required resources.",
                        compliance_category="Security Best Practices"
                    )
        except ClientError as e:
            print(f"Error checking role for {func_name}: {e}")

    def _check_runtime(self, func_name, func_arn, runtime):
        if runtime and runtime in DEPRECATED_RUNTIMES:
            self.add_finding(
                check_id="LAMBDA-03", 
                check_name="Deprecated runtime", 
                resource_id=func_name, 
                resource_arn=func_arn,
                severity="High",
                description=f"Function uses deprecated runtime '{runtime}'.",
                recommendation="Upgrade to a supported runtime version to receive security patches.",
                compliance_category="Security Best Practices"
            )

    def _check_vpc(self, func_name, func_arn, vpc_config):
        if not vpc_config or not vpc_config.get('SubnetIds'):
            self.add_finding(
                check_id="LAMBDA-04", 
                check_name="No VPC configured", 
                resource_id=func_name, 
                resource_arn=func_arn,
                severity="Medium",
                description="Function runs outside a VPC and cannot access private subnet resources securely.",
                recommendation="If the function accesses internal resources (like RDS or ElastiCache), deploy it within a VPC.",
                compliance_category="Architecture Best Practices"
            )

    def _check_env_secrets(self, func_name, func_arn, env_config):
        variables = env_config.get('Variables', {})
        for key in variables:
            key_upper = key.upper()
            for keyword in SENSITIVE_ENV_KEYWORDS:
                if keyword in key_upper:
                    self.add_finding(
                        check_id="LAMBDA-05", 
                        check_name="Environment variable secrets", 
                        resource_id=func_name, 
                        resource_arn=func_arn,
                        severity="High",
                        description=f"Environment variable '{key}' may contain sensitive data.",
                        recommendation="Store sensitive data in AWS Secrets Manager or Systems Manager Parameter Store.",
                        compliance_category="Security Best Practices"
                    )
                    return

    def _check_timeout(self, func_name, func_arn, timeout):
        if timeout > 300:
            self.add_finding(
                check_id="LAMBDA-06", 
                check_name="High timeout configuration", 
                resource_id=func_name, 
                resource_arn=func_arn,
                severity="Low",
                description=f"Function timeout is {timeout}s (> 300s). This may lead to high costs on runaway invocations.",
                recommendation="Review the function's execution time and lower the timeout to prevent cost spikes.",
                compliance_category="Cost Optimization"
            )

    def _check_memory(self, func_name, func_arn, memory):
        if memory > 3008:
            self.add_finding(
                check_id="LAMBDA-07", 
                check_name="Excessive memory allocation", 
                resource_id=func_name, 
                resource_arn=func_arn,
                severity="Low",
                description=f"Function has {memory} MB of memory allocated (> 3008 MB).",
                recommendation="Use AWS Compute Optimizer to right-size the Lambda function's memory.",
                compliance_category="Cost Optimization"
            )

    def _check_dlq(self, func_name, func_arn, dlq_config):
        if not dlq_config or not dlq_config.get('TargetArn'):
            try:
                destinations = self.client.get_function_event_invoke_config(FunctionName=func_name)
                on_failure = destinations.get('DestinationConfig', {}).get('OnFailure', {})
                if on_failure.get('Destination'):
                    return 
            except ClientError:
                pass

            self.add_finding(
                check_id="LAMBDA-08", 
                check_name="No dead-letter queue", 
                resource_id=func_name, 
                resource_arn=func_arn,
                severity="Medium",
                description="Function has no DLQ or on-failure destination.",
                recommendation="Configure a Dead Letter Queue (DLQ) or On-Failure destination to capture failed async events.",
                compliance_category="Operational Excellence"
            )

    def _check_role_wildcard_resource(self, func_name, func_arn, role_arn):
        if not role_arn:
            return
        role_name = role_arn.split('/')[-1]
        try:
            inline_policies = self.iam.list_role_policies(RoleName=role_name)['PolicyNames']
            for policy_name in inline_policies:
                doc = self.iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
                statements = doc.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get('Effect') == 'Allow':
                        resources = stmt.get('Resource', [])
                        if isinstance(resources, str):
                            resources = [resources]
                        if '*' in resources:
                            self.add_finding(
                                check_id="LAMBDA-09", 
                                check_name="Wildcard resource in execution role", 
                                resource_id=func_name, 
                                resource_arn=func_arn,
                                severity="High",
                                description=f"Inline policy '{policy_name}' on role '{role_name}' grants 'Resource': '*'.",
                                recommendation="Scope down IAM policies to specific resource ARNs.",
                                compliance_category="Security Best Practices"
                            )
                            return
        except ClientError as e:
            print(f"Error checking inline policies for {func_name}: {e}")

    def _check_function_url_cors(self, func_name, func_arn):
        try:
            url_config = self.client.get_function_url_config(FunctionName=func_name)
            cors = url_config.get('Cors', {})
            origins = cors.get('AllowOrigins', [])
            if '*' in origins:
                self.add_finding(
                    check_id="LAMBDA-10", 
                    check_name="CORS wildcard on function URL", 
                    resource_id=func_name, 
                    resource_arn=func_arn,
                    severity="Medium",
                    description="Function URL allows CORS requests from any origin ('*').",
                    recommendation="Restrict AllowedOrigins to specific trusted domains.",
                    compliance_category="Security Best Practices"
                )
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                print(f"Error checking function URL for {func_name}: {e}")

    def _check_tracing(self, func_name, func_arn, tracing_config):
        if tracing_config.get('Mode') != 'Active':
            self.add_finding(
                check_id="LAMBDA-11", 
                check_name="Tracing disabled", 
                resource_id=func_name, 
                resource_arn=func_arn,
                severity="Low",
                description="AWS X-Ray active tracing is not enabled.",
                recommendation="Enable AWS X-Ray Active Tracing to improve observability and debugging.",
                compliance_category="Operational Excellence"
            )

    def _check_staleness(self, func_name, func_arn, last_modified):
        if not last_modified:
            return
        try:
            modified_date = datetime.datetime.fromisoformat(last_modified.replace('+0000', '+00:00'))
            age_days = (datetime.datetime.now(datetime.timezone.utc) - modified_date).days
            if age_days > 180:
                self.add_finding(
                    check_id="LAMBDA-12", 
                    check_name="Stale / unused functions", 
                    resource_id=func_name, 
                    resource_arn=func_arn,
                    severity="Low",
                    description=f"Function has not been modified in {age_days} days (> 180).",
                    recommendation="Review and delete stale Lambda functions to reduce attack surface and clutter.",
                    compliance_category="Operational Excellence"
                )
        except (ValueError, TypeError):
            pass

    def _check_code_signing(self, func_name, func_arn):
        try:
            config = self.client.get_function_code_signing_config(FunctionName=func_name)
            if not config.get('CodeSigningConfigArn'):
                self.add_finding(
                    check_id="LAMBDA-13", 
                    check_name="Code signing not enabled", 
                    resource_id=func_name, 
                    resource_arn=func_arn,
                    severity="Medium",
                    description="Function does not use Code Signing.",
                    recommendation="Configure AWS Signer to ensure only trusted, approved code is deployed.",
                    compliance_category="Security Best Practices"
                )
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                self.add_finding(
                    check_id="LAMBDA-13", 
                    check_name="Code signing not enabled", 
                    resource_id=func_name, 
                    resource_arn=func_arn,
                    severity="Medium",
                    description="Function does not use Code Signing.",
                    recommendation="Configure AWS Signer to ensure only trusted, approved code is deployed.",
                    compliance_category="Security Best Practices"
                )

    def _check_reserved_concurrency(self, func_name, func_arn):
        try:
            response = self.client.get_function_concurrency(FunctionName=func_name)
            if 'ReservedConcurrentExecutions' not in response:
                self.add_finding(
                    check_id="LAMBDA-14", 
                    check_name="No reserved concurrency", 
                    resource_id=func_name, 
                    resource_arn=func_arn,
                    severity="Low",
                    description="Function has no reserved concurrency limit.",
                    recommendation="Set a reserved concurrency limit to prevent this function from exhausting account-wide limits.",
                    compliance_category="Operational Excellence"
                )
        except ClientError:
            pass

    def _check_env_kms(self, func_name, func_arn, kms_arn):
        if not kms_arn:
            self.add_finding(
                check_id="LAMBDA-15", 
                check_name="Default KMS key for Env Vars", 
                resource_id=func_name, 
                resource_arn=func_arn,
                severity="Low",
                description="Function uses the default AWS-managed key for encryption.",
                recommendation="If using environment variables, encrypt them with a Customer Managed Key (CMK) instead of the default key.",
                compliance_category="Security Best Practices"
            )

if __name__ == "__main__":
    import json
    scanner = LambdaScanner()
    scanner.scan()
    print(json.dumps(scanner.findings, indent=4))
