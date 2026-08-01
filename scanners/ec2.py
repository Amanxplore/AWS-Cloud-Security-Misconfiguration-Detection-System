"""
EC2 Security Scanner Module
---------------------------
This module implements the 12 EC2 security checks as defined in the AWS Risk Engine project.
Inherits from BaseScanner for unified finding schema.
"""

import datetime
from botocore.exceptions import ClientError
import json
from .base import BaseScanner

class EC2Scanner(BaseScanner):
    def __init__(self, session=None):
        super().__init__(service_name='ec2', session=session)

    def scan(self):
        print("Starting EC2 Security Scan...")
        self._check_security_groups()
        self._check_instances()
        self._check_volumes()
        self._check_elastic_ips()
        self._check_snapshots()
        return self.findings

    def _check_security_groups(self):
        try:
            sgs = self.client.describe_security_groups()['SecurityGroups']
            
            # Check 4: Unused security groups (Requires network interfaces lookup to verify usage)
            used_sgs = set()
            enis = self.client.describe_network_interfaces()['NetworkInterfaces']
            for eni in enis:
                for group in eni.get('Groups', []):
                    used_sgs.add(group['GroupId'])

            for sg in sgs:
                sg_id = sg['GroupId']
                sg_arn = f"arn:aws:ec2:{self.region}:{self.account_id}:security-group/{sg_id}"
                
                # EC2-04 Unused security groups
                if sg_id not in used_sgs and sg['GroupName'] != 'default':
                    self.add_finding(
                        check_id="EC2-04", 
                        check_name="Unused security groups", 
                        resource_id=sg_id, 
                        resource_arn=sg_arn,
                        severity="Low", 
                        description="Security group is not attached to any ENI.",
                        recommendation="Remove unused security groups to keep firewall configurations clean.",
                        compliance_category="Security Best Practices"
                    )
                
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    to_port = rule.get('ToPort', -1)
                    from_port = rule.get('FromPort', -1)
                    
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            # EC2-01 SSH open to the world
                            if to_port == 22:
                                self.add_finding(
                                    check_id="EC2-01", 
                                    check_name="SSH open to the world", 
                                    resource_id=sg_id, 
                                    resource_arn=sg_arn,
                                    severity="Critical", 
                                    description="Security group allows inbound TCP port 22 from 0.0.0.0/0.",
                                    recommendation="Restrict SSH access to specific IP addresses (e.g., corporate VPN or Bastion hosts).",
                                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (5.2)"
                                )
                            
                            # EC2-02 RDP open to the world
                            elif to_port == 3389:
                                self.add_finding(
                                    check_id="EC2-02", 
                                    check_name="RDP open to the world", 
                                    resource_id=sg_id, 
                                    resource_arn=sg_arn,
                                    severity="Critical", 
                                    description="Security group allows inbound TCP port 3389 from 0.0.0.0/0.",
                                    recommendation="Restrict RDP access to specific IP addresses (e.g., corporate VPN or Bastion hosts).",
                                    compliance_category="CIS AWS Foundations Benchmark v1.4.0 (5.3)"
                                )
                            
                            # EC2-03 All ports open
                            elif from_port == -1 and to_port == -1:
                                self.add_finding(
                                    check_id="EC2-03", 
                                    check_name="All ports open", 
                                    resource_id=sg_id, 
                                    resource_arn=sg_arn,
                                    severity="Critical", 
                                    description="Security group allows inbound traffic on all ports from 0.0.0.0/0.",
                                    recommendation="Implement least privilege for inbound rules. Do not allow all ports to be open to the internet.",
                                    compliance_category="Security Best Practices"
                                )
        except ClientError as e:
            print(f"Error checking security groups: {e}")

    def _check_instances(self):
        try:
            reservations = self.client.describe_instances()['Reservations']
            for res in reservations:
                for instance in res.get('Instances', []):
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{self.region}:{self.account_id}:instance/{instance_id}"
                    
                    # EC2-06 Public IP on instances
                    if instance.get('PublicIpAddress'):
                        self.add_finding(
                            check_id="EC2-06", 
                            check_name="Public IP on instances", 
                            resource_id=instance_id, 
                            resource_arn=instance_arn,
                            severity="Medium", 
                            description="EC2 instance has a public IP address assigned.",
                            recommendation="Place instances in private subnets and use ALBs or NAT Gateways for internet access.",
                            compliance_category="Security Best Practices"
                        )
                        
                    # EC2-07 Default security group in use
                    for sg in instance.get('SecurityGroups', []):
                        if sg['GroupName'] == 'default':
                            self.add_finding(
                                check_id="EC2-07", 
                                check_name="Default security group in use", 
                                resource_id=instance_id, 
                                resource_arn=instance_arn,
                                severity="Medium", 
                                description="Instance is using the default VPC security group.",
                                recommendation="Create specific security groups for each application tier instead of using the default group.",
                                compliance_category="CIS AWS Foundations Benchmark v1.4.0 (5.4)"
                            )
                    
                    # EC2-08 No IMDSv2 enforced
                    metadata_options = instance.get('MetadataOptions', {})
                    if metadata_options.get('HttpTokens') != 'required':
                        self.add_finding(
                            check_id="EC2-08", 
                            check_name="No IMDSv2 enforced", 
                            resource_id=instance_id, 
                            resource_arn=instance_arn,
                            severity="High", 
                            description="Instance metadata service allows IMDSv1.",
                            recommendation="Require IMDSv2 on all instances to prevent SSRF attacks.",
                            compliance_category="Security Best Practices"
                        )

                    # EC2-10 Outdated AMI usage
                    image_id = instance.get('ImageId')
                    try:
                        ami_info = self.client.describe_images(ImageIds=[image_id]).get('Images', [])
                        if ami_info:
                            # Using split on '.' to safely handle milliseconds
                            creation_date = datetime.datetime.strptime(ami_info[0]['CreationDate'].split('.')[0], '%Y-%m-%dT%H:%M:%S')
                            if (datetime.datetime.now() - creation_date).days > 365:
                                self.add_finding(
                                    check_id="EC2-10", 
                                    check_name="Outdated AMI usage", 
                                    resource_id=instance_id, 
                                    resource_arn=instance_arn,
                                    severity="Medium", 
                                    description=f"Instance is using an AMI ({image_id}) older than 1 year.",
                                    recommendation="Update instances to use recently patched and approved AMIs.",
                                    compliance_category="Security Best Practices"
                                )
                    except ClientError:
                        pass

                    # EC2-11 No termination protection
                    try:
                        term_prot = self.client.describe_instance_attribute(InstanceId=instance_id, Attribute='disableApiTermination')
                        if not term_prot.get('DisableApiTermination', {}).get('Value'):
                            self.add_finding(
                                check_id="EC2-11", 
                                check_name="No termination protection", 
                                resource_id=instance_id, 
                                resource_arn=instance_arn,
                                severity="Low", 
                                description="Instance does not have termination protection enabled.",
                                recommendation="Enable termination protection for critical or production instances.",
                                compliance_category="Operational Excellence"
                            )
                    except ClientError:
                        pass
        except ClientError as e:
            print(f"Error checking instances: {e}")

    def _check_volumes(self):
        try:
            volumes = self.client.describe_volumes()['Volumes']
            for volume in volumes:
                volume_id = volume['VolumeId']
                volume_arn = f"arn:aws:ec2:{self.region}:{self.account_id}:volume/{volume_id}"
                
                # EC2-05 Unencrypted EBS volumes
                if not volume.get('Encrypted'):
                    self.add_finding(
                        check_id="EC2-05", 
                        check_name="Unencrypted EBS volumes", 
                        resource_id=volume_id, 
                        resource_arn=volume_arn,
                        severity="High", 
                        description="EBS volume is not encrypted at rest.",
                        recommendation="Enable EBS encryption by default at the account level and encrypt existing volumes.",
                        compliance_category="CIS AWS Foundations Benchmark v1.4.0 (2.2.1)"
                    )
        except ClientError as e:
            print(f"Error checking volumes: {e}")

    def _check_elastic_ips(self):
        try:
            addresses = self.client.describe_addresses()['Addresses']
            for address in addresses:
                # EC2-09 Unused Elastic IPs
                if 'InstanceId' not in address:
                    allocation_id = address.get('AllocationId', address.get('PublicIp', 'Unknown'))
                    eip_arn = f"arn:aws:ec2:{self.region}:{self.account_id}:eip-allocation/{allocation_id}"
                    
                    self.add_finding(
                        check_id="EC2-09", 
                        check_name="Unused Elastic IPs", 
                        resource_id=address.get('PublicIp', 'Unknown'), 
                        resource_arn=eip_arn,
                        severity="Low", 
                        description="Elastic IP is allocated but not associated with an instance.",
                        recommendation="Release unused Elastic IPs to avoid unnecessary AWS charges.",
                        compliance_category="Cost Optimization"
                    )
        except ClientError as e:
            print(f"Error checking elastic IPs: {e}")
            
    def _check_snapshots(self):
        try:
            # We only look at self-owned snapshots
            snapshots = self.client.describe_snapshots(OwnerIds=['self'])['Snapshots']
            for snap in snapshots:
                snap_id = snap['SnapshotId']
                snap_arn = f"arn:aws:ec2:{self.region}:{self.account_id}:snapshot/{snap_id}"
                
                # EC2-12 Snapshots publicly shared
                attrs = self.client.describe_snapshot_attribute(SnapshotId=snap_id, Attribute='createVolumePermission')
                for perm in attrs.get('CreateVolumePermissions', []):
                    if perm.get('Group') == 'all':
                        self.add_finding(
                            check_id="EC2-12", 
                            check_name="Snapshots publicly shared", 
                            resource_id=snap_id, 
                            resource_arn=snap_arn,
                            severity="Critical", 
                            description="EBS snapshot is shared publicly.",
                            recommendation="Remove the 'all' group from snapshot permissions to ensure they are private.",
                            compliance_category="Security Best Practices"
                        )
        except ClientError as e:
            print(f"Error checking snapshots: {e}")

if __name__ == "__main__":
    import json
    scanner = EC2Scanner()
    scanner.scan()
    print(json.dumps(scanner.findings, indent=4))
