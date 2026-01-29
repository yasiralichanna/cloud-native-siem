import json
import boto3
import os
from datetime import datetime, timedelta
import requests
from botocore.exceptions import ClientError
import re
import hashlib
from typing import Dict, List, Any, Optional
import uuid

# Initialize AWS clients
securityhub = boto3.client('securityhub')
s3 = boto3.client('s3')
eventbridge = boto3.client('events')
cloudtrail = boto3.client('cloudtrail')
guardduty = boto3.client('guardduty')
ssm = boto3.client('ssm')
sns = boto3.client('sns')

# Configuration from environment variables
ES_ENDPOINT = os.environ.get('ES_ENDPOINT', 'http://localhost:9200')
OPENCTI_URL = os.environ.get('OPENCTI_URL', 'http://localhost:8080')
OPENCTI_TOKEN = os.environ.get('OPENCTI_TOKEN', '')
ALERT_TOPIC_ARN = os.environ.get('ALERT_TOPIC_ARN')
S3_BUCKET = os.environ.get('S3_BUCKET', 'security-response-logs')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')

# MITRE ATT&CK Mapping Database (Extended)
MITRE_TECHNIQUES = {
    # Initial Access
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1566": "Phishing",
    
    # Execution
    "T1059": "Command and Scripting Interpreter",
    "T1203": "Exploitation for Client Execution",
    "T1569": "System Services",
    
    # Persistence
    "T1136": "Create Account",
    "T1547": "Boot or Logon Autostart Execution",
    "T1574": "Hijack Execution Flow",
    
    # Privilege Escalation
    "T1068": "Exploitation for Privilege Escalation",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1578": "Modify Cloud Compute Infrastructure",
    
    # Defense Evasion
    "T1070": "Indicator Removal on Host",
    "T1112": "Modify Registry",
    "T1562": "Impair Defenses",
    
    # Credential Access
    "T1110": "Brute Force",
    "T1555": "Credentials from Password Stores",
    "T1557": "Man-in-the-Middle",
    
    # Discovery
    "T1083": "File and Directory Discovery",
    "T1135": "Network Share Discovery",
    "T1518": "Software Discovery",
    
    # Lateral Movement
    "T1021": "Remote Services",
    "T1210": "Exploitation of Remote Services",
    "T1570": "Lateral Tool Transfer",
    
    # Collection
    "T1113": "Screen Capture",
    "T1115": "Clipboard Data",
    "T1560": "Archive Collected Data",
    
    # Exfiltration
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1567": "Exfiltration Over Web Service",
    "T1020": "Automated Exfiltration",
    
    # Impact
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery"
}

MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0040": "Impact"
}

# Pattern mapping for automatic detection
PATTERN_MAPPING = {
    r"brute.*force|multiple.*failed.*logins": ["TA0006", "T1110"],
    r"port.*scan|scanning.*ports": ["TA0043", "T1046"],
    r"data.*exfil|exfiltration": ["TA0010", "T1048"],
    r"privilege.*escalat|escalation.*privileges": ["TA0004", "T1068"],
    r"persistence|backdoor": ["TA0003", "T1136"],
    r"defense.*evasion|evading.*detection": ["TA0005", "T1070"],
    r"credential.*dump|dump.*credentials": ["TA0006", "T1003"],
    r"lateral.*movement|move.*laterally": ["TA0008", "T1021"],
    r"command.*control|c2": ["TA0011", "T1071"],
    r"data.*destruction|destroy.*data": ["TA0040", "T1485"],
    r"ransomware|encrypt.*files": ["TA0040", "T1486"],
    r"phishing|spear.*phishing": ["TA0001", "T1566"],
    r"sql.*injection|inject.*sql": ["TA0001", "T1190"],
    r"cross.*site|xs.s": ["TA0001", "T1190"],
    r"malware|trojan|virus": ["TA0002", "T1204"],
    r"keylogger|keystroke.*logging": ["TA0009", "T1056"]
}

class SIEMProcessor:
    def __init__(self):
        self.es_endpoint = ES_ENDPOINT
        self.opencti_url = OPENCTI_URL
        self.opencti_token = OPENCTI_TOKEN
        self.cache = {}
        
    def map_to_mitre(self, title: str, description: str, details: Dict) -> tuple:
        """Map security event to MITRE ATT&CK framework"""
        tactics = set()
        techniques = set()
        
        # Combine text for pattern matching
        text_to_analyze = f"{title} {description} {json.dumps(details)}".lower()
        
        # Pattern matching
        for pattern, mitre_codes in PATTERN_MAPPING.items():
            if re.search(pattern, text_to_analyze, re.IGNORECASE):
                tactics.add(mitre_codes[0])
                techniques.add(mitre_codes[1])
        
        # Additional logic based on AWS service
        if 'ProductFields' in details:
            product_fields = details['ProductFields']
            if 'aws/guardduty' in str(product_fields):
                tactics.add("TA0001")  # Initial Access
                techniques.add("T1190")  # Exploit Public-Facing Application
            elif 'aws/securityhub' in str(product_fields):
                if 'ComplianceStatus' in product_fields:
                    tactics.add("TA0005")  # Defense Evasion
        
        # If no matches found, use generic mapping
        if not tactics:
            tactics.add("TA0001")  # Initial Access
            techniques.add("T1190")  # Exploit Public-Facing Application
        
        return list(tactics), list(techniques)
    
    def enrich_with_threat_intel(self, indicators: List[str]) -> Dict:
        """Enrich event with threat intelligence"""
        enriched_data = {
            "opencti": {},
            "vt_lookup": {},
            "abuseipdb": {}
        }
        
        for indicator in indicators:
            # OpenCTI enrichment
            if self.opencti_token and indicator:
                enriched_data["opencti"][indicator] = self.query_opencti(indicator)
            
            # VirusTotal lookup (simulated - would require API key)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
                enriched_data["vt_lookup"][indicator] = self.simulate_vt_lookup(indicator)
            
            # AbuseIPDB lookup (simulated)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
                enriched_data["abuseipdb"][indicator] = self.simulate_abuseipdb_lookup(indicator)
        
        return enriched_data
    
    def query_opencti(self, indicator: str) -> Dict:
        """Query OpenCTI for threat intelligence"""
        try:
            headers = {
                "Authorization": f"Bearer {self.opencti_token}",
                "Content-Type": "application/json"
            }
            
            query = """
            query {
                indicators(filters: {key: "indicator_pattern", values: ["%s"]}) {
                    edges {
                        node {
                            id
                            name
                            pattern_type
                            pattern
                            valid_from
                            valid_until
                            score
                            createdBy {
                                name
                            }
                            markingDefinitions {
                                definition
                            }
                        }
                    }
                }
            }
            """ % indicator
            
            response = requests.post(
                f"{self.opencti_url}/graphql",
                json={"query": query},
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data', {}).get('indicators', {}).get('edges'):
                    return data['data']['indicators']['edges'][0]['node']
        except Exception as e:
            print(f"OpenCTI query failed for {indicator}: {e}")
        
        return {}
    
    def simulate_vt_lookup(self, ip: str) -> Dict:
        """Simulate VirusTotal lookup (replace with actual API call)"""
        return {
            "malicious": hash(ip) % 10 == 0,  # 10% chance for demo
            "suspicious": hash(ip) % 5 == 0,  # 20% chance for demo
            "harmless": hash(ip) % 2 == 0,    # 50% chance for demo
            "undetected": hash(ip) % 3 == 0,  # 33% chance for demo
            "last_analysis_date": datetime.utcnow().isoformat()
        }
    
    def simulate_abuseipdb_lookup(self, ip: str) -> Dict:
        """Simulate AbuseIPDB lookup (replace with actual API call)"""
        return {
            "abuse_confidence_score": hash(ip) % 100,
            "total_reports": hash(ip) % 50,
            "last_reported_at": (datetime.utcnow() - timedelta(days=hash(ip) % 30)).isoformat()
        }
    
    def generate_response_playbook(self, finding: Dict) -> List[Dict]:
        """Generate automated response playbook based on finding"""
        severity = finding.get('Severity', {}).get('Label', 'LOW')
        resource_type = finding.get('Resources', [{}])[0].get('Type', '')
        resource_id = finding.get('Resources', [{}])[0].get('Id', '')
        
        base_actions = []
        
        # Common actions for all severities
        base_actions.append({
            "action": "log_to_s3",
            "parameters": {
                "bucket": S3_BUCKET,
                "key": f"findings/{datetime.utcnow().strftime('%Y/%m/%d')}/{finding.get('Id')}.json"
            }
        })
        
        if severity == "HIGH":
            high_severity_actions = [
                {
                    "action": "isolate_resource",
                    "parameters": {
                        "resource_type": resource_type,
                        "resource_id": resource_id
                    },
                    "priority": "IMMEDIATE"
                },
                {
                    "action": "notify_security_team",
                    "parameters": {
                        "channel": "security-alerts-high",
                        "message": f"CRITICAL: {finding.get('Title')}"
                    },
                    "priority": "IMMEDIATE"
                },
                {
                    "action": "create_incident_ticket",
                    "parameters": {
                        "severity": "SEV-1",
                        "title": finding.get('Title'),
                        "description": finding.get('Description')
                    }
                },
                {
                    "action": "block_indicators",
                    "parameters": {
                        "ips": self.extract_ips(finding),
                        "domains": self.extract_domains(finding)
                    }
                }
            ]
            base_actions.extend(high_severity_actions)
        
        elif severity == "MEDIUM":
            medium_severity_actions = [
                {
                    "action": "notify_security_team",
                    "parameters": {
                        "channel": "security-alerts-medium",
                        "message": f"WARNING: {finding.get('Title')}"
                    }
                },
                {
                    "action": "schedule_investigation",
                    "parameters": {
                        "due_in_hours": 24
                    }
                }
            ]
            base_actions.extend(medium_severity_actions)
        
        elif severity == "LOW":
            low_severity_actions = [
                {
                    "action": "log_for_weekly_review",
                    "parameters": {
                        "review_date": (datetime.utcnow() + timedelta(days=7)).strftime('%Y-%m-%d')
                    }
                }
            ]
            base_actions.extend(low_severity_actions)
        
        # Add MITRE-specific actions
        tactics = finding.get('mitre_tactics', [])
        if "TA0006" in tactics:  # Credential Access
            base_actions.append({
                "action": "force_password_reset",
                "parameters": {
                    "users": self.extract_usernames(finding)
                }
            })
        
        if "TA0004" in tactics:  # Privilege Escalation
            base_actions.append({
                "action": "review_iam_roles",
                "parameters": {
                    "resource_arn": resource_id if 'arn:' in resource_id else None
                }
            })
        
        return base_actions
    
    def extract_ips(self, finding: Dict) -> List[str]:
        """Extract IP addresses from finding"""
        ips = []
        text = json.dumps(finding).lower()
        
        # Extract IPv4 addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips.extend(re.findall(ip_pattern, text))
        
        # Extract from specific fields
        resources = finding.get('Resources', [])
        for resource in resources:
            if 'IpAddress' in resource:
                ips.append(resource['IpAddress'])
        
        return list(set(ips))
    
    def extract_domains(self, finding: Dict) -> List[str]:
        """Extract domain names from finding"""
        domains = []
        text = json.dumps(finding).lower()
        
        # Simple domain pattern
        domain_pattern = r'\b(?:[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b'
        domains.extend(re.findall(domain_pattern, text))
        
        return list(set(domains))
    
    def extract_usernames(self, finding: Dict) -> List[str]:
        """Extract usernames from finding"""
        usernames = []
        text = json.dumps(finding)
        
        # Look for common username patterns
        patterns = [
            r'user[:\s]+([a-zA-Z0-9._-]+)',
            r'username[:\s]+([a-zA-Z0-9._-]+)',
            r'principal[:\s]+([a-zA-Z0-9._-]+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            usernames.extend(matches)
        
        return list(set(usernames))
    
    def index_to_elasticsearch(self, event: Dict) -> bool:
        """Index event to Elasticsearch"""
        try:
            # Create index if it doesn't exist
            index_name = f"siem-{ENVIRONMENT}-{datetime.utcnow().strftime('%Y-%m')}"
            
            # Check if index exists
            response = requests.head(f"{self.es_endpoint}/{index_name}")
            
            if response.status_code == 404:
                # Create index with mapping
                index_mapping = {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0,
                        "analysis": {
                            "analyzer": {
                                "threat_analyzer": {
                                    "type": "custom",
                                    "tokenizer": "standard",
                                    "filter": ["lowercase", "asciifolding"]
                                }
                            }
                        }
                    },
                    "mappings": {
                        "properties": {
                            "@timestamp": {"type": "date"},
                            "event": {"type": "object", "enabled": True},
                            "mitre_tactics": {"type": "keyword"},
                            "mitre_techniques": {"type": "keyword"},
                            "threat_intel": {"type": "object", "enabled": True},
                            "response_actions": {"type": "object", "enabled": True},
                            "severity": {"type": "keyword"},
                            "resource_type": {"type": "keyword"},
                            "source": {"type": "keyword"}
                        }
                    }
                }
                
                create_response = requests.put(
                    f"{self.es_endpoint}/{index_name}",
                    json=index_mapping,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                
                if create_response.status_code not in [200, 201]:
                    print(f"Failed to create index: {create_response.text}")
            
            # Index the document
            doc_id = hashlib.md5(json.dumps(event).encode()).hexdigest()
            index_response = requests.put(
                f"{self.es_endpoint}/{index_name}/_doc/{doc_id}",
                json=event,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            return index_response.status_code in [200, 201]
            
        except Exception as e:
            print(f"Elasticsearch indexing failed: {e}")
            return False
    
    def execute_response_actions(self, actions: List[Dict], finding: Dict):
        """Execute response actions"""
        executed_actions = []
        
        for action in actions:
            try:
                action_name = action.get('action')
                parameters = action.get('parameters', {})
                
                if action_name == "isolate_resource":
                    self.isolate_resource(
                        parameters.get('resource_type'),
                        parameters.get('resource_id')
                    )
                
                elif action_name == "notify_security_team":
                    self.notify_security_team(
                        parameters.get('channel'),
                        parameters.get('message'),
                        finding
                    )
                
                elif action_name == "log_to_s3":
                    self.log_to_s3(
                        parameters.get('bucket'),
                        parameters.get('key'),
                        finding
                    )
                
                elif action_name == "block_indicators":
                    self.block_indicators(
                        parameters.get('ips', []),
                        parameters.get('domains', [])
                    )
                
                elif action_name == "force_password_reset":
                    self.force_password_reset(
                        parameters.get('users', [])
                    )
                
                executed_actions.append({
                    "action": action_name,
                    "status": "SUCCESS",
                    "timestamp": datetime.utcnow().isoformat()
                })
                
            except Exception as e:
                executed_actions.append({
                    "action": action.get('action'),
                    "status": "FAILED",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                })
                print(f"Failed to execute action {action.get('action')}: {e}")
        
        return executed_actions
    
    def isolate_resource(self, resource_type: str, resource_id: str):
        """Isolate a resource (EC2 instance)"""
        if resource_type == "AwsEc2Instance" and resource_id.startswith('i-'):
            ec2 = boto3.client('ec2')
            
            # Describe instance to get VPC
            instances = ec2.describe_instances(InstanceIds=[resource_id])
            if instances['Reservations']:
                vpc_id = instances['Reservations'][0]['Instances'][0]['VpcId']
                
                # Create isolated security group
                sg_response = ec2.create_security_group(
                    GroupName=f'isolated-{resource_id}',
                    Description=f'Isolated security group for {resource_id}',
                    VpcId=vpc_id
                )
                
                isolated_sg_id = sg_response['GroupId']
                
                # Remove all inbound/outbound rules
                ec2.revoke_security_group_ingress(
                    GroupId=isolated_sg_id,
                    IpPermissions=[{
                        'IpProtocol': '-1',
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }]
                )
                
                ec2.revoke_security_group_egress(
                    GroupId=isolated_sg_id,
                    IpPermissions=[{
                        'IpProtocol': '-1',
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }]
                )
                
                # Apply isolated security group to instance
                ec2.modify_instance_attribute(
                    InstanceId=resource_id,
                    Groups=[isolated_sg_id]
                )
    
    def notify_security_team(self, channel: str, message: str, finding: Dict):
        """Notify security team via SNS"""
        if ALERT_TOPIC_ARN:
            sns = boto3.client('sns')
            
            alert_message = {
                "channel": channel,
                "message": message,
                "finding_id": finding.get('Id'),
                "severity": finding.get('Severity', {}).get('Label'),
                "timestamp": datetime.utcnow().isoformat(),
                "mitre_tactics": finding.get('mitre_tactics', []),
                "mitre_techniques": finding.get('mitre_techniques', []),
                "resource": finding.get('Resources', [{}])[0].get('Id', 'Unknown')
            }
            
            sns.publish(
                TopicArn=ALERT_TOPIC_ARN,
                Subject=f"Security Alert: {finding.get('Title', 'Unknown')}",
                Message=json.dumps(alert_message, indent=2)
            )
    
    def log_to_s3(self, bucket: str, key: str, data: Dict):
        """Log data to S3"""
        s3 = boto3.client('s3')
        
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(data, indent=2),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
    
    def block_indicators(self, ips: List[str], domains: List[str]):
        """Block malicious indicators (simulated)"""
        # In production, this would update WAF rules, NACLs, etc.
        print(f"Would block IPs: {ips}")
        print(f"Would block domains: {domains}")
        
        # Example: Update WAF IP Set
        # waf = boto3.client('wafv2')
        # waf.update_ip_set(...)
    
    def force_password_reset(self, users: List[str]):
        """Force password reset for users"""
        iam = boto3.client('iam')
        
        for username in users:
            try:
                iam.update_login_profile(
                    UserName=username,
                    PasswordResetRequired=True
                )
                print(f"Forced password reset for user: {username}")
            except Exception as e:
                print(f"Failed to force password reset for {username}: {e}")
    
    def process_finding(self, finding: Dict) -> Dict:
        """Process a single security finding"""
        # Map to MITRE ATT&CK
        tactics, techniques = self.map_to_mitre(
            finding.get('Title', ''),
            finding.get('Description', ''),
            finding.get('ProductFields', {})
        )
        
        # Extract indicators for enrichment
        indicators = self.extract_ips(finding) + self.extract_domains(finding)
        
        # Enrich with threat intelligence
        threat_intel = self.enrich_with_threat_intel(indicators)
        
        # Generate response playbook
        response_actions = self.generate_response_playbook(finding)
        
        # Create enriched event
        enriched_event = {
            **finding,
            "mitre_tactics": tactics,
            "mitre_techniques": techniques,
            "mitre_tactic_names": [MITRE_TACTICS.get(t, t) for t in tactics],
            "mitre_technique_names": [MITRE_TECHNIQUES.get(t, t) for t in techniques],
            "threat_intel": threat_intel,
            "response_actions": response_actions,
            "processed_at": datetime.utcnow().isoformat(),
            "processor_version": "1.0.0",
            "environment": ENVIRONMENT
        }
        
        # Index to Elasticsearch
        if self.index_to_elasticsearch(enriched_event):
            enriched_event["es_indexed"] = True
        else:
            enriched_event["es_indexed"] = False
        
        # Execute response actions for high severity
        severity = finding.get('Severity', {}).get('Label', 'LOW')
        if severity in ["HIGH", "CRITICAL"]:
            executed_actions = self.execute_response_actions(response_actions, finding)
            enriched_event["executed_actions"] = executed_actions
        
        return enriched_event

# Global processor instance
processor = SIEMProcessor()

def lambda_handler(event, context):
    """Main Lambda handler"""
    print(f"Received event: {json.dumps(event)[:500]}...")
    
    processed_findings = []
    
    try:
        # Process Security Hub findings
        if event.get('source') == 'aws.securityhub':
            findings = event.get('detail', {}).get('findings', [])
            
            for finding in findings:
                enriched_finding = processor.process_finding(finding)
                processed_findings.append(enriched_finding)
        
        # Process GuardDuty findings
        elif event.get('source') == 'aws.guardduty':
            guardduty_finding = event.get('detail', {})
            
            # Convert GuardDuty finding to Security Hub format
            security_hub_like_finding = {
                "SchemaVersion": "2018-10-08",
                "Id": guardduty_finding.get('id', str(uuid.uuid4())),
                "ProductArn": f"arn:aws:securityhub:{event.get('region')}::product/aws/guardduty",
                "GeneratorId": guardduty_finding.get('type', 'GuardDuty'),
                "AwsAccountId": guardduty_finding.get('accountId', ''),
                "Types": ["TTPs/Discovery"],
                "CreatedAt": guardduty_finding.get('createdAt', datetime.utcnow().isoformat()),
                "UpdatedAt": guardduty_finding.get('updatedAt', datetime.utcnow().isoformat()),
                "Severity": {"Label": guardduty_finding.get('severity', 5) / 2},  # Convert 0-10 to 0-5
                "Title": guardduty_finding.get('title', 'GuardDuty Finding'),
                "Description": guardduty_finding.get('description', ''),
                "Resources": guardduty_finding.get('resource', {}).get('instanceDetails', {}).get('instanceId', [{}])[0],
                "ProductFields": guardduty_finding
            }
            
            enriched_finding = processor.process_finding(security_hub_like_finding)
            processed_findings.append(enriched_finding)
        
        # Process CloudTrail events (if configured)
        elif 'detail-type' in event and event['detail-type'] == 'AWS API Call via CloudTrail':
            # Process CloudTrail events
            cloudtrail_event = event.get('detail', {})
            
            # Check for suspicious API calls
            suspicious_apis = [
                'CreateUser', 'CreateAccessKey', 'AuthorizeSecurityGroupIngress',
                'PutRolePolicy', 'ModifyInstanceAttribute', 'StopLogging'
            ]
            
            if cloudtrail_event.get('eventName') in suspicious_apis:
                suspicious_finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"cloudtrail-{cloudtrail_event.get('eventID')}",
                    "ProductArn": f"arn:aws:securityhub:{event.get('region')}::product/aws/cloudtrail",
                    "GeneratorId": "CloudTrail-SIEM",
                    "AwsAccountId": cloudtrail_event.get('userIdentity', {}).get('accountId', ''),
                    "Types": ["UnauthorizedAccess"],
                    "CreatedAt": cloudtrail_event.get('eventTime', datetime.utcnow().isoformat()),
                    "UpdatedAt": datetime.utcnow().isoformat(),
                    "Severity": {"Label": "MEDIUM"},
                    "Title": f"Suspicious API Call: {cloudtrail_event.get('eventName')}",
                    "Description": f"User {cloudtrail_event.get('userIdentity', {}).get('arn')} called {cloudtrail_event.get('eventName')}",
                    "Resources": [{"Type": "AwsAccount", "Id": cloudtrail_event.get('userIdentity', {}).get('accountId', '')}],
                    "ProductFields": cloudtrail_event
                }
                
                enriched_finding = processor.process_finding(suspicious_finding)
                processed_findings.append(enriched_finding)
        
        # Log processing results
        print(f"Processed {len(processed_findings)} findings")
        
        # Create summary metric
        summary = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_findings": len(processed_findings),
            "findings_by_severity": {},
            "findings_by_mitre_tactic": {},
            "environment": ENVIRONMENT
        }
        
        for finding in processed_findings:
            severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
            summary["findings_by_severity"][severity] = summary["findings_by_severity"].get(severity, 0) + 1
            
            for tactic in finding.get('mitre_tactics', []):
                summary["findings_by_mitre_tactic"][tactic] = summary["findings_by_mitre_tactic"].get(tactic, 0) + 1
        
        # Store summary in S3
        processor.log_to_s3(
            S3_BUCKET,
            f"summaries/{datetime.utcnow().strftime('%Y/%m/%d/%H')}/summary-{datetime.utcnow().strftime('%H%M')}.json",
            summary
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'processed_findings': len(processed_findings),
                'summary': summary,
                'timestamp': datetime.utcnow().isoformat()
            })
        }
        
    except Exception as e:
        print(f"Error processing event: {e}")
        print(f"Event context: {event}")
        
        # Log error to S3
        error_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
            "event": event,
            "context": str(context) if context else None
        }
        
        processor.log_to_s3(
            S3_BUCKET,
            f"errors/{datetime.utcnow().strftime('%Y/%m/%d')}/error-{datetime.utcnow().strftime('%H%M%S')}.json",
            error_log
        )
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'processed_findings': len(processed_findings)
            })
        }