#!/usr/bin/env python3
"""
AWS Cloud Assessment Script

This script performs a comprehensive assessment of an AWS environment using only the AWS CLI
and standard Python libraries. It collects information about various AWS resources and generates
a detailed report with findings and recommendations.

Requirements:
- Python 3.6+
- AWS CLI configured with appropriate permissions
- boto3 library (for AWS CLI interaction)

Usage:
    python aws_assessment.py [--output-dir OUTPUT_DIR] [--regions REGIONS]
"""

 boto3
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

    def assess_eks(self, region):
        """Assess EKS clusters for security and configuration issues."""
        print(f"Assessing EKS in {region}...")
        
        # Get EKS clusters
        clusters = self._run_aws_cli("eks", "list-clusters", 
                                  query="clusters[]", 
                                  region=region)
        
        # Check each cluster
        for cluster_name in clusters:
            cluster_info = self._run_aws_cli("eks", "describe-cluster", 
                                          query="cluster", 
                                          region=region)
            
            if not cluster_info:
                continue
                
            self.resources["eks_clusters"].append(cluster_info)
            
            # Check Kubernetes version
            k8s_version = cluster_info.get("version")
            if k8s_version and (k8s_version.startswith("1.1") or k8s_version.startswith("1.20") or k8s_version.startswith("1.21")):
                self.findings.append({
                    "severity": "HIGH",
                    "resource_type": "EKS Cluster",
                    "resource_id": cluster_name,
                    "region": region,
                    "finding": f"Cluster is running older Kubernetes version ({k8s_version})",
                    "recommendation": "Upgrade to a newer Kubernetes version for improved security and features"
                })
            
            # Check encryption
            encryption = cluster_info.get("encryptionConfig")
            if not encryption:
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "EKS Cluster",
                    "resource_id": cluster_name,
                    "region": region,
                    "finding": "Cluster does not have encryption configured",
                    "recommendation": "Enable encryption for EKS cluster resources"
                })
            
            # Check public endpoint access
            endpoint_access = cluster_info.get("resourcesVpcConfig", {}).get("endpointPublicAccess")
            if endpoint_access:
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "EKS Cluster",
                    "resource_id": cluster_name,
                    "region": region,
                    "finding": "Cluster endpoint is publicly accessible",
                    "recommendation": "Disable public access to the Kubernetes API server endpoint when possible"
                })
    
    def assess_ecs(self, region):
        """Assess ECS clusters for security and configuration issues."""
        print(f"Assessing ECS in {region}...")
        
        # Get ECS clusters
        clusters = self._run_aws_cli("ecs", "list-clusters", 
                                  query="clusterArns[]", 
                                  region=region)
        
        # Check each cluster
        for cluster_arn in clusters:
            cluster_name = cluster_arn.split("/")[-1]
            
            # Get services in the cluster
            services = self._run_aws_cli("ecs", "list-services", 
                                      query="serviceArns[]", 
                                      region=region)
            
            for service_arn in services:
                service_name = service_arn.split("/")[-1]
                service_info = self._run_aws_cli("ecs", "describe-services", 
                                              query="services[]", 
                                              region=region)
                
                if not service_info:
                    continue
                    
                self.resources["ecs_services"].append(service_info)
                
                # Check for public IP assignment
                for service in service_info:
                    network_config = service.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
                    public_ip = network_config.get("assignPublicIp", "")
                    
                    if public_ip == "ENABLED":
                        self.findings.append({
                            "severity": "MEDIUM",
                            "resource_type": "ECS Service",
                            "resource_id": service_name,
                            "region": region,
                            "finding": "Service is assigned public IP addresses",
                            "recommendation": "Consider disabling public IP assignment for ECS tasks when possible"
                        })
            
            # Get task definitions
            task_definitions = self._run_aws_cli("ecs", "list-task-definitions", 
                                              query="taskDefinitionArns[]", 
                                              region=region)
            
            for task_def_arn in task_definitions:
                task_def_name = task_def_arn.split("/")[-1]
                task_def_info = self._run_aws_cli("ecs", "describe-task-definition", 
                                               query="taskDefinition", 
                                               region=region)
                
                if not task_def_info:
                    continue
                    
                self.resources["ecs_task_definitions"].append(task_def_info)
                
                # Check for privileged containers
                containers = task_def_info.get("containerDefinitions", [])
                for container in containers:
                    privileged = container.get("privileged", False)
                    
                    if privileged:
                        self.findings.append({
                            "severity": "HIGH",
                            "resource_type": "ECS Task Definition",
                            "resource_id": task_def_name,
                            "region": region,
                            "finding": f"Container '{container.get('name')}' is running in privileged mode",
                            "recommendation": "Avoid using privileged mode for containers unless absolutely necessary"
                        })
    
    def assess_elasticache(self, region):
        """Assess ElastiCache clusters for security and configuration issues."""
        print(f"Assessing ElastiCache in {region}...")
        
        # Get ElastiCache clusters
        clusters = self._run_aws_cli("elasticache", "describe-cache-clusters", 
                                  query="CacheClusters[]", 
                                  region=region)
        
        self.resources["elasticache_clusters"].extend(clusters)
        
        # Check each cluster
        for cluster in clusters:
            cluster_id = cluster.get("CacheClusterId")
            encryption_transit = cluster.get("TransitEncryptionEnabled", False)
            cache_subnet_group = cluster.get("CacheSubnetGroupName")
            
            # Check encryption in transit
            if not encryption_transit:
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "ElastiCache Cluster",
                    "resource_id": cluster_id,
                    "region": region,
                    "finding": "Cluster does not have encryption in transit enabled",
                    "recommendation": "Enable encryption in transit for ElastiCache clusters"
                })
            
            # Check if in a subnet group
            if not cache_subnet_group:
                self.findings.append({
                    "severity": "LOW",
                    "resource_type": "ElastiCache Cluster",
                    "resource_id": cluster_id,
                    "region": region,
                    "finding": "Cluster is not in a cache subnet group",
                    "recommendation": "Place ElastiCache clusters in a dedicated subnet group for better network isolation"
                })
    
    def assess_apigateway(self, region):
        """Assess API Gateway for security and configuration issues."""
        print(f"Assessing API Gateway in {region}...")
        
        # Get API Gateway REST APIs
        rest_apis = self._run_aws_cli("apigateway", "get-rest-apis", 
                                   query="items[]", 
                                   region=region)
        
        self.resources["apigateway_rest_apis"].extend(rest_apis)
        
        # Check each API
        for api in rest_apis:
            api_id = api.get("id")
            api_name = api.get("name")
            
            # Check stages
            stages = self._run_aws_cli("apigateway", "get-stages", 
                                    query="item[]", 
                                    region=region)
            
            for stage in stages:
                stage_name = stage.get("stageName")
                
                # Check for logging
                logging_enabled = False
                method_settings = stage.get("methodSettings", {})
                for method, settings in method_settings.items():
                    if settings.get("loggingLevel") in ["INFO", "ERROR"]:
                        logging_enabled = True
                        break
                
                if not logging_enabled:
                    self.findings.append({
                        "severity": "LOW",
                        "resource_type": "API Gateway Stage",
                        "resource_id": f"{api_name}/{stage_name}",
                        "region": region,
                        "finding": "API Gateway logging is not enabled",
                        "recommendation": "Enable logging for API Gateway stages to monitor API usage and errors"
                    })
                
                # Check for throttling
                throttling_enabled = False
                for method, settings in method_settings.items():
                    if settings.get("throttlingBurstLimit") and settings.get("throttlingRateLimit"):
                        throttling_enabled = True
                        break
                
                if not throttling_enabled:
                    self.findings.append({
                        "severity": "LOW",
                        "resource_type": "API Gateway Stage",
                        "resource_id": f"{api_name}/{stage_name}",
                        "region": region,
                        "finding": "API Gateway throttling is not configured",
                        "recommendation": "Configure throttling to protect your backend services from traffic spikes"
                    })
    
    def assess_sns(self, region):
        """Assess SNS topics for security and configuration issues."""
        print(f"Assessing SNS in {region}...")
        
        # Get SNS topics
        topics = self._run_aws_cli("sns", "list-topics", 
                                query="Topics[]", 
                                region=region)
        
        # Check each topic
        for topic in topics:
            topic_arn = topic.get("TopicArn")
            topic_name = topic_arn.split(":")[-1]
            
            # Get topic attributes
            attributes = self._run_aws_cli("sns", "get-topic-attributes", 
                                        query="Attributes", 
                                        region=region)
            
            if not attributes:
                continue
                
            self.resources["sns_topics"].append(attributes)
            
            # Check encryption
            encryption = attributes.get("KmsMasterKeyId")
            if not encryption:
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "SNS Topic",
                    "resource_id": topic_name,
                    "region": region,
                    "finding": "Topic does not have encryption enabled",
                    "recommendation": "Enable encryption for sensitive SNS topics"
                })
    
    def assess_sqs(self, region):
        """Assess SQS queues for security and configuration issues."""
        print(f"Assessing SQS in {region}...")
        
        # Get SQS queues
        queues = self._run_aws_cli("sqs", "list-queues", 
                                query="QueueUrls[]", 
                                region=region)
        
        # Check each queue
        for queue_url in queues:
            queue_name = queue_url.split("/")[-1]
            
            # Get queue attributes
            attributes = self._run_aws_cli("sqs", "get-queue-attributes", 
                                        query="Attributes", 
                                        region=region)
            
            if not attributes:
                continue
                
            self.resources["sqs_queues"].append(attributes)
            
            # Check encryption
            encryption = attributes.get("KmsMasterKeyId")
            if not encryption:
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "SQS Queue",
                    "resource_id": queue_name,
                    "region": region,
                    "finding": "Queue does not have encryption enabled",
                    "recommendation": "Enable encryption for sensitive SQS queues"
                })
            
            # Check for DLQ
            dlq_arn = attributes.get("RedrivePolicy", {}).get("deadLetterTargetArn")
            if not dlq_arn:
                self.findings.append({
                    "severity": "LOW",
                    "resource_type": "SQS Queue",
                    "resource_id": queue_name,
                    "region": region,
                    "finding": "Queue does not have a dead-letter queue configured",
                    "recommendation": "Configure dead-letter queues for important SQS queues to capture failed messages"
                })
    
    def assess_route53(self):
        """Assess Route53 domains and DNS configurations."""
        print("Assessing Route53...")
        
        # Get hosted zones
        zones = self._run_aws_cli("route53", "list-hosted-zones", 
                               query="HostedZones[]")
        
        self.resources["route53_zones"] = zones
        
        # Check each zone
        for zone in zones:
            zone_id = zone.get("Id").split("/")[-1]
            zone_name = zone.get("Name")
            
            # Check for DNSSEC
            dnssec = self._run_aws_cli("route53", "get-dnssec", 
                                    query="Status", 
                                    region=None)
            
            if not dnssec or dnssec.get("ServeSignature") != "SIGNED":
                self.findings.append({
                    "severity": "LOW",
                    "resource_type": "Route53 Hosted Zone",
                    "resource_id": zone_name,
                    "finding": "DNSSEC is not enabled for the hosted zone",
                    "recommendation": "Consider enabling DNSSEC for critical domains to prevent DNS spoofing"
                })
    
    def assess_cloudfront(self):
        """Assess CloudFront distributions for security and configuration issues."""
        print("Assessing CloudFront...")
        
        # Get CloudFront distributions
        distributions = self._run_aws_cli("cloudfront", "list-distributions", 
                                       query="DistributionList.Items[]")
        
        self.resources["cloudfront_distributions"] = distributions
        
        # Check each distribution
        for distribution in distributions:
            dist_id = distribution.get("Id")
            https_only = distribution.get("ViewerCertificate", {}).get("MinimumProtocolVersion") != "SSLv3"
            geo_restrictions = distribution.get("Restrictions", {}).get("GeoRestriction", {}).get("Quantity", 0) > 0
            waf_id = distribution.get("WebACLId")
            
            # Check for HTTPS
            if not https_only:
                self.findings.append({
                    "severity": "HIGH",
                    "resource_type": "CloudFront Distribution",
                    "resource_id": dist_id,
                    "finding": "Distribution allows outdated SSL/TLS protocols",
                    "recommendation": "Configure distribution to use TLSv1.2 or later only"
                })
            
            # Check for WAF
            if not waf_id:
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "CloudFront Distribution",
                    "resource_id": dist_id,
                    "finding": "Distribution does not have WAF protection",
                    "recommendation": "Consider adding a WAF to protect CloudFront distributions from web attacks"
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
                                          query="KeyRotationEnabled", 
                                          region=region)
                
                if not rotation:
                    self.findings.append({
                        "severity": "MEDIUM",
                        "resource_type": "KMS Key",
                        "resource_id": key_id,
                        "region": region,
                        "finding": "Key rotation is not enabled",
                        "recommendation": "Enable automatic key rotation for KMS keys"
                    })
            except Exception:
                # Some AWS-managed keys cannot have rotation status checked
                pass
            
            # Check key state
            key_state = key_details.get("KeyState")
            if key_state == "PendingDeletion":
                self.findings.append({
                    "severity": "MEDIUM",
                    "resource_type": "KMS Key",
                    "resource_id": key_id,
                    "region": region,
                    "finding": "Key is pending deletion",
                    "recommendation": "Verify if the key should be deleted or recovered"
                })

    def assess_elb(self, region):
        """Assess Elastic Load Balancers for security and configuration issues."""
        print(f"Assessing ELB in {region}...")
        
        # Get Classic Load Balancers
        classic_lbs = self._run_aws_cli("elb", "describe-load-balancers", 
                                     query="LoadBalancerDescriptions[]", 
                                     region=region)
        
        self.resources["classic_load_balancers"].extend(classic_lbs)
        
        # Get Application and Network Load Balancers
        v2_lbs = self._run_aws_cli("elbv2", "describe-load-balancers", 
                                 query="LoadBalancers[]", 
                                 region=region)
        
        self.resources["elbv2_load_balancers"].extend(v2_lbs)
        
        # Check Classic Load Balancers
        for lb in classic_lbs:
            lb_name = lb.get("LoadBalancerName")
            listeners = lb.get("ListenerDescriptions", [])
            
            # Check for insecure listeners
            for listener in listeners:
                protocol = listener.get("Listener", {}).get("Protocol", "").upper()
                lb_port = listener.get("Listener", {}).get("LoadBalancerPort")
                
                if protocol in ["HTTP", "TCP"]:
                    self.findings.append({
                        "severity": "MEDIUM",
                        "resource_type": "Classic Load Balancer",
                        "resource_id": lb_name,
                        "region": region,
                        "finding": f"Load balancer using insecure protocol {protocol} on port {lb_port}",
                        "recommendation": "Use HTTPS or SSL for all public-facing load balancers"
                    })
        
        # Check v2 Load Balancers (ALB/NLB)
        for lb in v2_lbs:
            lb_name = lb.get("LoadBalancerName")
            lb_arn = lb.get("LoadBalancerArn")
            lb_type = lb.get("Type")
            scheme = lb.get("Scheme")
            
            # Check if internet-facing
            if scheme == "internet-facing":
                # Get listeners for this LB
                listeners = self._run_aws_cli("elbv2", "describe-listeners", 
                                           query="Listeners[]", 
                                           region=region)
                
                # Check for insecure listeners
                for listener in listeners:
                    protocol = listener.get("Protocol", "").upper()
                    port = listener.get("Port")
                    
                    if protocol in ["HTTP", "TCP"]:
                        self.findings.append({
                            "severity": "MEDIUM",
                            "resource_type": f"{lb_type} Load Balancer",
                            "resource_id": lb_name,
                            "region": region,
                            "finding": f"Internet-facing load balancer using insecure protocol {protocol} on port {port}",
                            "recommendation": "Use HTTPS or TLS for all internet-facing load balancers"
                        })
                
                # Check for WAF if ALB
                if lb_type == "application":
                    # Check if WAF is associated with this ALB
                    waf_acls = self._run_aws_cli("wafv2", "list-web-acls", 
                                              query="WebACLs[]", 
                                              region=region)
                    
                    waf_found = False
                    for acl in waf_acls:
                        resources = self._run_aws_cli("wafv2", "list-resources-for-web-acl", 
                                                   query="ResourceArns[]", 
                                                   region=region)
                        
                        if lb_arn in resources:
                            waf_found = True
                            break
                    
                    if not waf_found:
                        self.findings.append({
                            "severity": "LOW",
                            "resource_type": "Application Load Balancer",
                            "resource_id": lb_name,
                            "region": region,
                            "finding": "Internet-facing ALB has no WAF protection",
                            "recommendation": "Consider adding a WAF to protect internet-facing ALBs"
                        })
