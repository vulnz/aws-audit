#!/usr/bin/env python3
"""
AWS Cloud Assessment Script

This script performs a comprehensive assessment of an AWS environment using only the AWS CLI
and standard Python libraries. It collects information about various AWS resources and generates
a detailed report with findings and recommendations.

Requirements:
- Python 3.6+
- AWS CLI configured with appropriate permissions

Usage:
    python aws_assessment.py [--output-dir OUTPUT_DIR] [--regions REGIONS]
"""

import argparse
import csv
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Set, Tuple, Optional

class AWSAssessment:
    def __init__(self, regions=None, output_dir=None):
        """Initialize the AWS assessment tool."""
        self.regions = regions or self._get_all_regions()
        self.output_dir = output_dir or f"aws_assessment_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.account_id = self._get_account_id()
        self.findings = []
        self.resources = defaultdict(list)
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        print(f"Starting AWS assessment on account {self.account_id}")
        print(f"Scanning regions: {', '.join(self.regions)}")
        print(f"Results will be saved to: {os.path.abspath(self.output_dir)}")

    def _run_aws_cli(self, service, command, region=None, query=None) -> dict:
        """Run an AWS CLI command and return the JSON output."""
        cmd = ["aws", service, command]
        
        if region:
            cmd.extend(["--region", region])
        
        if query:
            cmd.extend(["--query", query])
            
        cmd.append("--output=json")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout) if result.stdout.strip() else {}
        except subprocess.CalledProcessError as e:
            if "AccessDenied" in e.stderr:
                print(f"Access denied for {' '.join(cmd)}")
                return {}
            elif "is not authorized to perform" in e.stderr:
                print(f"Not authorized to perform {' '.join(cmd)}")
                return {}
            elif "NoSuchEntity" in e.stderr or "NotFoundException" in e.stderr:
                return {}
            else:
                print(f"Error executing {' '.join(cmd)}: {e.stderr}")
                return {}
        except json.JSONDecodeError:
            print(f"Failed to parse JSON response from {' '.join(cmd)}")
            return {}

    def _get_account_id(self) -> str:
        """Get the current AWS account ID."""
        try:
            identity = self._run_aws_cli("sts", "get-caller-identity")
            return identity.get("Account", "unknown")
        except Exception as e:
            print(f"Error getting account ID: {e}")
            return "unknown"

    def _get_all_regions(self) -> List[str]:
        """Get a list of all available AWS regions."""
        try:
            regions = self._run_aws_cli("ec2", "describe-regions", query="Regions[].RegionName")
            return regions
        except Exception as e:
            print(f"Error getting AWS regions: {e}. Falling back to default regions.")
            # Fallback to common regions if we can't get the full list
            return ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-northeast-1", "ap-southeast-1"]

    def run_assessment(self):
        """Run the full AWS assessment."""
        start_time = time.time()
        
        # Collect global resource information (region-independent)
        self.assess_iam()
        self.assess_s3()
        self.assess_route53()
        self.assess_cloudfront()
        
        # Collect region-specific resource information
        with ThreadPoolExecutor(max_workers=min(10, len(self.regions))) as executor:
            for region in self.regions:
                executor.submit(self.assess_region, region)
        
        # Generate final report
        self.generate_report()
        
        duration = time.time() - start_time
        print(f"Assessment completed in {duration:.2f} seconds")
        print(f"Report saved to {os.path.join(os.path.abspath(self.output_dir), 'assessment_report.json')}")

    def assess_region(self, region):
        """Assess resources in a specific region."""
        print(f"Assessing region: {region}")
        
        # Compute services
        self.assess_ec2(region)
        self.assess_lambda(region)
        self.assess_eks(region)
        self.assess_ecs(region)
        
        # Storage services
        self.assess_rds(region)
        self.assess_dynamodb(region)
        self.assess_elasticache(region)
        
        # Network services
        self.assess_vpc(region)
        self.assess_elb(region)
        
        # Application services
        self.assess_apigateway(region)
        self.assess_sns(region)
        self.assess_sqs(region)
        
        # Security services
        self.assess_security_groups(region)
        self.assess_kms(region)
        self.assess_cloudtrail(region)
        
        print(f"Assessment for region {region} completed")

    def assess_iam(self):
        """Assess IAM users, roles, policies, and security configurations."""
        print("Assessing IAM...")
        
        # Get IAM users
        users = self._run_aws_cli("iam", "list-users", query="Users[]")
        self.resources["iam_users"] = users
        
        # Check for users without MFA
        for user in users:
            username = user.get("UserName")
            mfa_devices = self._run_aws_cli("iam", "list-mfa-devices", query="MFADevices[]", 
                                         region=None)
            
            if not mfa_devices:
                self.findings.append({
                    "severity": "HIGH",
                    "resource_type": "IAM User",
                    "resource_id": username,
                    "finding": "User does not have MFA enabled",
                    "recommendation": "Enable MFA for all IAM users"
                })
        
        # Get IAM roles
        roles = self._run_aws_cli("iam", "list-roles", query="Roles[]")
        self.resources["iam_roles"] = roles
        
        # Check for roles with overly permissive policies
        for role in roles:
            role_name = role.get("RoleName")
            attached_policies = self._run_aws_cli("iam", "list-attached-role-policies", 
                                               query="AttachedPolicies[]", 
                                               region=None)
            
            for policy in attached_policies:
                policy_arn = policy.get("PolicyArn")
                if "AdministratorAccess" in policy_arn:
                    self.findings.append({
                        "severity": "MEDIUM",
                        "resource_type": "IAM Role",
                        "resource_id": role_name,
                        "finding": f"Role has AdministratorAccess policy attached",
                        "recommendation": "Review if this role requires full administrative access"
                    })
        
        # Get IAM policies
        policies = self._run_aws_cli("iam", "list-policies", query="Policies[]", 
                                   region=None)
        self.resources["iam_policies"] = policies
        
        # Check for password policy
        password_policy = self._run_aws_cli("iam", "get-account-password-policy")
        
        if not password_policy:
            self.findings.append({
                "severity": "MEDIUM",
                "resource_type": "IAM Password Policy",
                "resource_id": "global",
                "finding": "No account password policy is configured",
                "recommendation": "Configure a strong password policy for the account"
            })
        else:
            min_length = password_policy.get("MinimumPasswordLength", 0)
            if min_length < 14:
                self.findings.append({
                    "severity": "LOW",
                    "resource_type": "IAM Password Policy",
                    "resource_id": "global",
                    "finding": f"Password minimum length is only {min_length} characters",
                    "recommendation": "Increase minimum password length to at least 14 characters"
                })

    def assess_ec2(self, region):
        """Assess EC2 instances, volumes, and related resources."""
        print(f"Assessing EC2 in {region}...")
        
        # Get EC2 instances
        instances = self._run_aws_cli("ec2", "describe-instances", 
                                   query="Reservations[].Instances[]", 
                                   region=region)
        
        self.resources["ec2_instances"].extend(instances)
        
        # Check for instances without encryption or with public IPs
        for instance in instances:
            instance_id = instance.get("InstanceId")
            instance_type = instance.get("InstanceType")
            
            # Check for public IP
            public_ip = instance.get("PublicIpAddress")
            if public_ip:
                self.findings.append({
                    "severity": "INFO",
                    "resource_type": "EC2 Instance",
                    "resource_id": instance_id,
                    "region": region,
                    "finding": f"Instance has a public IP address ({public_ip})",
                    "recommendation": "Ensure this instance requires public access"
                })
            
            # Check for unencrypted volumes
            block_devices = instance.get("BlockDeviceMappings", [])
            for device in block_devices:
                if "Ebs" in device:
                    volume_id = device["Ebs"].get("VolumeId")
                    volume_info = self._run_aws_cli("ec2", "describe-volumes", 
                                                 query=f"Volumes[?VolumeId=='{volume_id}']", 
                                                 region=region)
                    
                    if volume_info and not volume_info[0].get("Encrypted", False):
                        self.findings.append({
                            "severity": "MEDIUM",
                            "resource_type": "EC2 Volume",
                            "resource_id": volume_id,
                            "region": region,
                            "finding": "Volume is not encrypted",
                            "recommendation": "Enable encryption for all EBS volumes"
                        })
            
            # Check for outdated instance types
            if instance_type and instance_type.startswith(('t1.', 'm1.', 'm3.', 'c1.', 'c3.')):
                self.findings.append({
                    "severity": "LOW",
                    "resource_type": "EC2 Instance",
                    "resource_id": instance_id,
                    "region": region,
                    "finding": f"Instance using older generation instance type ({instance_type})",
                    "recommendation": "Consider upgrading to newer generation instance types for better performance and cost efficiency"
                })

    def assess_s3(self):
        """Assess S3 buckets and their configurations."""
        print("Assessing S3...")
        
        # Get S3 buckets
        buckets = self._run_aws_cli("s3api", "list-buckets", query="Buckets[]")
        self.resources["s3_buckets"] = buckets
        
        # Check each bucket for security configurations
        for bucket in buckets:
            bucket_name = bucket.get("Name")
            
            # Check bucket encryption
            try:
                encryption = self._run_aws_cli("s3api", "get-bucket-encryption", 
                                           region=None)
                
                if not encryption:
                    self.findings.append({
                        "severity": "HIGH",
                        "resource_type": "S3 Bucket",
                        "resource_id": bucket_name,
                        "finding": "Bucket does not have default encryption enabled",
                        "recommendation": "Enable default encryption for all S3 buckets"
                    })
            except Exception:
                # If we get an error, the bucket likely doesn't have encryption
                self.findings.append({
                    "severity": "HIGH",
                    "resource_type": "S3 Bucket",
                    "resource_id": bucket_name,
                    "finding": "Bucket does not have default encryption enabled",
                    "recommendation": "Enable default encryption for all S3 buckets"
                })
            
            # Check bucket public access settings
            public_access = self._run_aws_cli("s3api", "get-public-access-block", 
                                           region=None)
            
            if not public_access:
                self.findings.append({
                    "severity": "HIGH",
                    "resource_type": "S3 Bucket",
                    "resource_id": bucket_name,
                    "finding": "Bucket does not have public access blocks configured",
                    "recommendation": "Configure public access blocks for all S3 buckets"
                })
            
            # Check bucket policy for public access
            try:
                policy = self._run_aws_cli("s3api", "get-bucket-policy", 
                                        region=None)
                
                if policy and "Statement" in policy:
                    for statement in policy["Statement"]:
                        principal = statement.get("Principal", {})
                        if principal == "*" or principal.get("AWS") == "*":
                            self.findings.append({
                                "severity": "HIGH",
                                "resource_type": "S3 Bucket",
                                "resource_id": bucket_name,
                                "finding": "Bucket policy allows public access",
                                "recommendation": "Review and restrict bucket policy permissions"
                            })
            except Exception:
                # No policy or error reading policy
                pass

    def assess_vpc(self, region):
        """Assess VPC configurations and network security."""
        print(f"Assessing VPC in {region}...")
        
        # Get VPCs
        vpcs = self._run_aws_cli("ec2", "describe-vpcs", query="Vpcs[]", region=region)
        self.resources["vpcs"].extend(vpcs)
        
        # Get network ACLs
        nacls = self._run_aws_cli("ec2", "describe-network-acls", query="NetworkAcls[]", 
                               region=region)
        self.resources["network_acls"].extend(nacls)
        
        # Check for default VPCs
        for vpc in vpcs:
            vpc_id = vpc.get("VpcId")
            is_default = vpc.get("IsDefault", False)
            
            if is_default:
                self.findings.append({
                    "severity": "LOW",
                    "resource_type": "VPC",
                    "resource_id": vpc_id,
                    "region": region,
                    "finding": "Default VPC is being used",
                    "recommendation": "Consider removing default VPCs and creating custom VPCs with appropriate security controls"
                })
        
        # Check for overly permissive NACLs
        for nacl in nacls:
            nacl_id = nacl.get("NetworkAclId")
            entries = nacl.get("Entries", [])
            
            for entry in entries:
                if entry.get("Egress") is False and entry.get("CidrBlock") == "0.0.0.0/0" and entry.get("RuleAction") == "allow":
                    self.findings.append({
                        "severity": "MEDIUM",
                        "resource_type": "Network ACL",
                        "resource_id": nacl_id,
                        "region": region,
                        "finding": "Network ACL allows inbound traffic from any IP address",
                        "recommendation": "Restrict network ACL rules to specific IP ranges where possible"
                    })

    def assess_security_groups(self, region):
        """Assess security groups for overly permissive rules."""
        print(f"Assessing Security Groups in {region}...")
        
        # Get security groups
        security_groups = self._run_aws_cli("ec2", "describe-security-groups", 
                                         query="SecurityGroups[]", 
                                         region=region)
        
        self.resources["security_groups"].extend(security_groups)
        
        # Check for overly permissive security group rules
        for sg in security_groups:
            sg_id = sg.get("GroupId")
            sg_name = sg.get("GroupName")
            
            # Check inbound rules
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)
                ip_ranges = rule.get("IpRanges", [])
                
                for ip_range in ip_ranges:
                    cidr = ip_range.get("CidrIp", "")
                    
                    if cidr == "0.0.0.0/0":
                        # Critical ports open to the world
                        critical_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 1433: "MSSQL", 5432: "PostgreSQL", 27017: "MongoDB"}
                        
                        if from_port in critical_ports or to_port in critical_ports:
                            port_name = critical_ports.get(from_port) or critical_ports.get(to_port)
                            self.findings.append({
                                "severity": "HIGH",
                                "resource_type": "Security Group",
                                "resource_id": sg_id,
                                "region": region,
                                "finding": f"Security group allows {port_name} access from any IP address",
                                "recommendation": "Restrict access to specific IP ranges for sensitive services"
                            })
                        elif from_port == 0 and to_port == 0:
                            self.findings.append({
                                "severity": "HIGH",
                                "resource_type": "Security Group",
                                "resource_id": sg_id,
                                "region": region,
                                "finding": "Security group allows all traffic from any IP address",
                                "recommendation": "Restrict security group rules to specific ports and IP ranges"
                            })
                        else:
                            self.findings.append({
                                "severity": "MEDIUM",
                                "resource_type": "Security Group",
                                "resource_id": sg_id,
                                "region": region,
                                "finding": f"Security group allows access to ports {from_port}-{to_port} from any IP address",
                                "recommendation": "Restrict access to specific IP ranges where possible"
                            })

    def assess_rds(self, region):
        """Assess RDS instances and their security configurations."""
        print(f"Assessing RDS in {region}...")
        
        # Get RDS instances
        instances = self._run_aws_cli("rds", "describe-db-instances", 
                                   query="DBInstances[]", 
                                   region=region)
        
        self.resources["rds_instances"].extend(instances)
        
        # Check for security issues
        for instance in instances:
            instance_id = instance.get("DBInstanceIdentifier")
            storage_encrypted = instance.get("StorageEncrypted", False)
            publicly_accessible = instance.get("PubliclyAccessible", False)
            multi_az = instance.get("MultiAZ", False)
            engine = instance.get("Engine", "")
            engine_version = instance.get("EngineVersion", "")
            
            # Check encryption
            if not storage_encrypted:
                self.findings.append({
                    "severity": "HIGH",
                    "resource_type": "RDS Instance",
                    "resource_id": instance_id,
                    "region": region,
                    "finding": "RDS instance is not encrypted",
                    "recommendation": "Enable encryption for all RDS instances"
                })
            
            # Check public accessibility
            if publicly_accessible:
                self.findings.append({
                    "severity": "HIGH",
                    "resource_type": "RDS Instance",
                    "resource_id": instance_id,
                    "region": region,
                    "finding": "RDS instance is publicly accessible",
                    "recommendation": "Disable public accessibility for RDS instances where possible"
                })
            
            # Check Multi-AZ
            if not multi_az:
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "RDS Instance",
                    "resource_id": instance_id,
                    "region": region,
                    "finding": "RDS instance is not configured for Multi-AZ deployment",
                    "recommendation": "Enable Multi-AZ for production RDS instances for high availability"
                })
            
            # Check for outdated engine versions (simplified example)
            if engine == "mysql" and engine_version.startswith(("5.6", "5.7")):
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "RDS Instance",
                    "resource_id": instance_id,
                    "region": region,
                    "finding": f"RDS instance is running older MySQL version ({engine_version})",
                    "recommendation": "Upgrade to MySQL 8.0 or later for better performance and security"
                })
            elif engine == "postgres" and engine_version.startswith(("9.", "10.")):
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "RDS Instance",
                    "resource_id": instance_id,
                    "region": region,
                    "finding": f"RDS instance is running older PostgreSQL version ({engine_version})",
                    "recommendation": "Upgrade to PostgreSQL 13 or later for better performance and security"
                })

    def assess_lambda(self, region):
        """Assess Lambda functions for security and configuration issues."""
        print(f"Assessing Lambda in {region}...")
        
        # Get Lambda functions
        functions = self._run_aws_cli("lambda", "list-functions", 
                                   query="Functions[]", 
                                   region=region)
        
        self.resources["lambda_functions"].extend(functions)
        
        # Check each function
        for function in functions:
            function_name = function.get("FunctionName")
            runtime = function.get("Runtime", "")
            
            # Check for deprecated runtimes
            deprecated_runtimes = ["nodejs10.x", "nodejs8.10", "nodejs6.10", "nodejs4.3", 
                                 "python2.7", "python3.6", "ruby2.5", "dotnetcore2.1"]
            
            if runtime in deprecated_runtimes:
                self.findings.append({
                    "severity": "HIGH",
                    "resource_type": "Lambda Function",
                    "resource_id": function_name,
                    "region": region,
                    "finding": f"Function is using deprecated runtime ({runtime})",
                    "recommendation": "Update to a supported runtime version"
                })
            
            # Check for appropriate memory size
            memory_size = function.get("MemorySize", 0)
            if memory_size <= 128:
                self.findings.append({
                    "severity": "LOW",
                    "resource_type": "Lambda Function",
                    "resource_id": function_name,
                    "region": region,
                    "finding": f"Function has minimal memory allocation ({memory_size} MB)",
                    "recommendation": "Consider increasing memory allocation if function performs compute-intensive tasks"
                })
            
            # Check timeout settings
            timeout = function.get("Timeout", 0)
            if timeout >= 60:
                self.findings.append({
                    "severity": "INFO",
                    "resource_type": "Lambda Function",
                    "resource_id": function_name,
                    "region": region,
                    "finding": f"Function has a long timeout setting ({timeout} seconds)",
                    "recommendation": "Review if the long timeout is necessary, as it could lead to higher costs for hanging functions"
                })

    def assess_dynamodb(self, region):
        """Assess DynamoDB tables for security and configuration issues."""
        print(f"Assessing DynamoDB in {region}...")
        
        # Get DynamoDB tables
        tables = self._run_aws_cli("dynamodb", "list-tables", 
                                query="TableNames[]", 
                                region=region)
        
        # Check each table
        for table_name in tables:
            table_info = self._run_aws_cli("dynamodb", "describe-table", 
                                        query="Table", 
                                        region=region)
            
            if not table_info:
                continue
                
            self.resources["dynamodb_tables"].append(table_info)
            
            # Check for encryption
            encryption = self._run_aws_cli("dynamodb", "describe-table", 
                                        query="Table.SSEDescription", 
                                        region=region)
            
            if not encryption or encryption.get("Status") != "ENABLED":
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "DynamoDB Table",
                    "resource_id": table_name,
                    "region": region,
                    "finding": "Table does not have server-side encryption enabled",
                    "recommendation": "Enable encryption for all DynamoDB tables"
                })
            
            # Check for point-in-time recovery
            try:
                pitr = self._run_aws_cli("dynamodb", "describe-continuous-backups", 
                                      query="ContinuousBackupsDescription.PointInTimeRecoveryDescription", 
                                      region=region)
                
                if not pitr or pitr.get("PointInTimeRecoveryStatus") != "ENABLED":
                    self.findings.append({
                        "severity": "MEDIUM",
                        "resource_type": "DynamoDB Table",
                        "resource_id": table_name,
                        "region": region,
                        "finding": "Table does not have point-in-time recovery enabled",
                        "recommendation": "Enable point-in-time recovery for important DynamoDB tables"
                    })
            except Exception:
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "DynamoDB Table",
                    "resource_id": table_name,
                    "region": region,
                    "finding": "Could not determine point-in-time recovery status",
                    "recommendation": "Enable point-in-time recovery for important DynamoDB tables"
                })

    def assess_cloudtrail(self, region):
        """Assess CloudTrail for proper logging configuration."""
        print(f"Assessing CloudTrail in {region}...")
        
        # Get CloudTrail trails
        trails = self._run_aws_cli("cloudtrail", "describe-trails", 
                                query="trailList[]", 
                                region=region)
        
        self.resources["cloudtrail_trails"].extend(trails)
        
        if not trails:
            self.findings.append({
                "severity": "HIGH",
                "resource_type": "CloudTrail",
                "resource_id": "Global",
                "region": region,
                "finding": "No CloudTrail trails found in the region",
                "recommendation": "Enable CloudTrail logging for all regions"
            })
            return
        
        # Check each trail
        for trail in trails:
            trail_name = trail.get("Name")
            multi_region = trail.get("IsMultiRegionTrail", False)
            log_file_validation = trail.get("LogFileValidationEnabled", False)
            
            # Check if trail is multi-region
            if not multi_region:
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "CloudTrail Trail",
                    "resource_id": trail_name,
                    "region": region,
                    "finding": "Trail is not configured as multi-region",
                    "recommendation": "Configure CloudTrail to log events from all regions"
                })
            
            # Check if log file validation is enabled
            if not log_file_validation:
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "CloudTrail Trail",
                    "resource_id": trail_name,
                    "region": region,
                    "finding": "Log file validation is not enabled",
                    "recommendation": "Enable log file validation to ensure integrity of CloudTrail logs"
                })
            
            # Check trail status
            status = self._run_aws_cli("cloudtrail", "get-trail-status", 
                                     query="", 
                                     region=region)
            
            if status and not status.get("IsLogging", False):
                self.findings.append({
                    "severity": "HIGH",
                    "resource_type": "CloudTrail Trail",
                    "resource_id": trail_name,
                    "region": region,
                    "finding": "Trail logging is not enabled",
                    "recommendation": "Enable logging for the CloudTrail trail"
                })

    def assess_kms(self, region):
        """Assess KMS keys for proper configuration."""
        print(f"Assessing KMS in {region}...")
        
        # Get KMS keys
        keys = self._run_aws_cli("kms", "list-keys", 
                              query="Keys[]", 
                              region=region)
        
        # Check each key
        for key in keys:
            key_id = key.get("KeyId")
            
            # Get key details
            key_details = self._run_aws_cli("kms", "describe-key", 
                                         query="KeyMetadata", 
                                         region=region)
            
            if not key_details:
                continue
                
            self.resources["kms_keys"].append(key_details)
            
            # Check if key rotation is enabled
            try:
                rotation = self._run_aws_cli("kms", "get-key-rotation-status", 
                                          query="Key
