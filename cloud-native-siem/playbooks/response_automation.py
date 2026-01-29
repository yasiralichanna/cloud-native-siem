import boto3
import json
from datetime import datetime

class SecurityAutomation:
    def __init__(self):
        self.ssm = boto3.client('ssm')
        self.ec2 = boto3.client('ec2')
        self.iam = boto3.client('iam')
        self.sns = boto3.client('sns')
        
    def isolate_instance(self, instance_id):
        """Move instance to isolated security group"""
        try:
            # Create isolated security group if not exists
            response = self.ec2.create_security_group(
                GroupName='isolated-sg',
                Description='Isolated security group for compromised instances',
                VpcId=self.get_vpc_id(instance_id)
            )
            isolated_sg_id = response['GroupId']
            
            # Remove all existing security groups
            self.ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[isolated_sg_id]
            )
            
            # Log the action
            self.log_action('isolate_instance', instance_id)
            
            return True
        except Exception as e:
            print(f"Failed to isolate instance: {e}")
            return False
    
    def block_malicious_ip(self, ip_address, protocol='ALL'):
        """Add malicious IP to Network ACL"""
        vpc_id = self.get_main_vpc()
        
        # Find or create NACL
        nacls = self.ec2.describe_network_acls(Filters=[
            {'Name': 'vpc-id', 'Values': [vpc_id]}
        ])
        
        if nacls['NetworkAcls']:
            nacl_id = nacls['NetworkAcls'][0]['NetworkAclId']
            
            # Add deny rule
            self.ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=100,
                Protocol='-1' if protocol == 'ALL' else protocol,
                RuleAction='deny',
                Egress=False,
                CidrBlock=f"{ip_address}/32"
            )
            
            self.log_action('block_ip', ip_address)
            return True
        return False
    
    def revoke_compromised_credentials(self, user_arn):
        """Revoke all active sessions and credentials"""
        try:
            # Extract username from ARN
            username = user_arn.split('/')[-1]
            
            # List and deactivate access keys
            keys = self.iam.list_access_keys(UserName=username)
            for key in keys['AccessKeyMetadata']:
                self.iam.update_access_key(
                    UserName=username,
                    AccessKeyId=key['AccessKeyId'],
                    Status='Inactive'
                )
            
            # Create password reset requirement
            self.iam.update_login_profile(
                UserName=username,
                PasswordResetRequired=True
            )
            
            self.log_action('revoke_credentials', username)
            return True
        except Exception as e:
            print(f"Failed to revoke credentials: {e}")
            return False
    
    def execute_ssm_document(self, instance_id, document_name):
        """Execute SSM document for remediation"""
        response = self.ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName=document_name,
            Parameters={
                'Action': ['ScanAndClean']
            }
        )
        return response['Command']['CommandId']
    
    def log_action(self, action, target):
        """Log all response actions"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'target': target,
            'executed_by': 'automated-playbook'
        }
        
        # Store in S3
        s3 = boto3.client('s3')
        s3.put_object(
            Bucket='security-response-logs',
            Key=f"actions/{datetime.now().strftime('%Y/%m/%d')}/{action}-{datetime.now().timestamp()}.json",
            Body=json.dumps(log_entry)
        )