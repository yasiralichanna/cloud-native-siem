#!/bin/bash

# Enable AWS Security Hub
aws securityhub enable-security-hub --region us-east-1

# Enable Security Hub standards
aws securityhub batch-enable-standards \
    --standards-subscription-requests '[{"StandardsArn":"arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"}]'

# Enable GuardDuty
aws guardduty create-detector --enable --region us-east-1

# Enable CloudTrail
aws cloudtrail create-trail \
    --name SecurityTrail \
    --s3-bucket-name siem-logs-$(date +%s) \
    --is-multi-region-trail \
    --enable-log-file-validation

# Configure CloudTrail to Security Hub integration
aws securityhub create-action-target \
    --name "HighSeverityFindings" \
    --description "Findings with HIGH severity" \
    --id "HighSeverityTarget"