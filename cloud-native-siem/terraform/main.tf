terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }

  backend "s3" {
    # Configure this based on your S3 bucket
    # bucket = "your-terraform-state-bucket"
    # key    = "cloud-native-siem/terraform.tfstate"
    # region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# IAM Role for Lambda
resource "aws_iam_role" "siem_lambda_role" {
  name = "${var.project_name}-lambda-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name = "${var.project_name}-lambda-role"
  }
}

# CloudWatch Logs Policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.siem_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Custom policy for SIEM operations
resource "aws_iam_role_policy" "siem_policy" {
  name = "${var.project_name}-siem-policy-${var.environment}"
  role = aws_iam_role.siem_lambda_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "securityhub:*",
          "cloudtrail:LookupEvents",
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "events:*",
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "logs:*",
          "ec2:DescribeInstances",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkAcls",
          "ec2:CreateNetworkAclEntry",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey",
          "iam:UpdateLoginProfile",
          "ssm:SendCommand",
          "ssm:ListCommands",
          "sns:Publish"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

# Lambda Function
resource "aws_lambda_function" "siem_processor" {
  filename      = "../lambda/siem-processor.zip"
  function_name = "${var.project_name}-processor-${var.environment}"
  role          = aws_iam_role.siem_lambda_role.arn
  handler       = "security_processor.lambda_handler"
  runtime       = "python3.9"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  environment {
    variables = {
      ES_ENDPOINT      = var.elasticsearch_endpoint
      OPENCTI_URL      = var.opencti_url
      OPENCTI_TOKEN    = "changeme"  # Set via AWS Console or Parameter Store
      ALERT_TOPIC_ARN  = aws_sns_topic.security_alerts.arn
      ENVIRONMENT      = var.environment
    }
  }

  tags = {
    Name = "${var.project_name}-processor"
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy.siem_policy
  ]
}

# EventBridge Rule for Security Hub
resource "aws_cloudwatch_event_rule" "securityhub_to_siem" {
  name        = "${var.project_name}-securityhub-rule-${var.environment}"
  description = "Capture Security Hub findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })

  tags = {
    Name = "${var.project_name}-securityhub-rule"
  }
}

# EventBridge Rule for GuardDuty
resource "aws_cloudwatch_event_rule" "guardduty_to_siem" {
  name        = "${var.project_name}-guardduty-rule-${var.environment}"
  description = "Capture GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  tags = {
    Name = "${var.project_name}-guardduty-rule"
  }
}

# EventBridge Targets
resource "aws_cloudwatch_event_target" "securityhub_target" {
  rule      = aws_cloudwatch_event_rule.securityhub_to_siem.name
  target_id = "SIEMLambda"
  arn       = aws_lambda_function.siem_processor.arn
}

resource "aws_cloudwatch_event_target" "guardduty_target" {
  rule      = aws_cloudwatch_event_rule.guardduty_to_siem.name
  target_id = "SIEMLambda"
  arn       = aws_lambda_function.siem_processor.arn
}

# Lambda Permissions for EventBridge
resource "aws_lambda_permission" "allow_eventbridge_securityhub" {
  statement_id  = "AllowExecutionFromEventBridgeSecurityHub"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.siem_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_to_siem.arn
}

resource "aws_lambda_permission" "allow_eventbridge_guardduty" {
  statement_id  = "AllowExecutionFromEventBridgeGuardDuty"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.siem_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_to_siem.arn
}

# SNS Topic for Alerts
resource "aws_sns_topic" "security_alerts" {
  name = "${var.project_name}-alerts-${var.environment}"
  
  tags = {
    Name = "${var.project_name}-alerts"
  }
}

# SNS Subscription (Email)
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = "security-team@example.com"  # Change to your email
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.siem_processor.function_name}"
  retention_in_days = 30
  
  tags = {
    Name = "${var.project_name}-lambda-logs"
  }
}

# S3 Bucket for Response Logs
resource "aws_s3_bucket" "response_logs" {
  bucket = "${var.project_name}-response-logs-${var.environment}-${random_id.bucket_suffix.hex}"
  
  tags = {
    Name = "${var.project_name}-response-logs"
  }
}

resource "aws_s3_bucket_versioning" "response_logs_versioning" {
  bucket = aws_s3_bucket.response_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "response_logs_encryption" {
  bucket = aws_s3_bucket.response_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "response_logs_lifecycle" {
  bucket = aws_s3_bucket.response_logs.id

  rule {
    id     = "transition_to_glacier"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# Random ID for S3 bucket name
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# SSM Document for remediation
resource "aws_ssm_document" "security_remediation" {
  name          = "${var.project_name}-remediation-${var.environment}"
  document_type = "Command"
  document_format = "YAML"

  content = <<-DOC
    schemaVersion: "2.2"
    description: "Security remediation actions for compromised instances"
    parameters:
      Action:
        type: "String"
        description: "Action to perform"
        allowedValues:
          - "ScanAndClean"
          - "CollectForensics"
          - "IsolateNetwork"
    mainSteps:
    - action: "aws:runShellScript"
      name: "Remediate"
      inputs:
        runCommand:
          - "echo 'Starting security remediation for instance {{ global:INSTANCE_ID }}'"
          - "date"
          - "whoami"
          - "netstat -tuln"
    DOC

  tags = {
    Name = "${var.project_name}-remediation"
  }
}