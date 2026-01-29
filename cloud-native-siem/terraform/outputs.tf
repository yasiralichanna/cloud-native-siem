output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.siem_processor.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.siem_processor.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.securityhub_to_siem.arn
}

output "iam_role_arn" {
  description = "ARN of the IAM role for Lambda"
  value       = aws_iam_role.siem_lambda_role.arn
}

output "security_hub_region" {
  description = "Region where Security Hub is enabled"
  value       = var.aws_region
}

output "kibana_url" {
  description = "Kibana dashboard URL"
  value       = "http://localhost:5601"
}

output "opencti_url" {
  description = "OpenCTI interface URL"
  value       = var.opencti_url
}