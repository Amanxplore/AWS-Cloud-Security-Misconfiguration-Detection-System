import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Optional, Any

class BaseScanner:
    """
    Base class for all AWS security scanners.
    Provides standardized methods for initializing boto3 clients, fetching Account ID,
    and enforcing a consistent findings schema across all services.
    """
    
    def __init__(self, service_name: str, session: Optional[boto3.Session] = None):
        self.service_name = service_name
        self.session = session if session else boto3.Session()
        self.client = self.session.client(service_name)
        
        # We need the STS client to get the Account ID
        self.sts = self.session.client('sts')
        try:
            self.account_id = self.sts.get_caller_identity().get('Account')
        except ClientError:
            self.account_id = "UNKNOWN"
            
        self.region = self.session.region_name or "us-east-1"
        self.findings: List[Dict[str, Any]] = []

    def add_finding(
        self, 
        check_id: str, 
        check_name: str, 
        resource_id: str, 
        severity: str, 
        description: str,
        recommendation: str = "Review AWS Security best practices for this service.",
        resource_arn: str = "N/A",
        compliance_category: str = "Security Best Practices"
    ) -> None:
        """
        Adds a standardized finding to the findings list.
        """
        self.findings.append({
            "check_id": check_id,
            "check_name": check_name,
            "resource_id": resource_id,
            "resource_arn": resource_arn,
            "region": self.region,
            "aws_service": self.service_name.upper(),
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "compliance_category": compliance_category
        })
        
    def scan(self) -> List[Dict[str, Any]]:
        """
        Must be implemented by child classes.
        Returns the populated self.findings list.
        """
        raise NotImplementedError("Child scanners must implement the scan() method.")
