variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the project for resource tagging"
  type        = string
  default     = "cloud-native-siem"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "development"
}

variable "elasticsearch_endpoint" {
  description = "Elasticsearch endpoint URL"
  type        = string
  default     = "http://localhost:9200"
}

variable "opencti_url" {
  description = "OpenCTI URL"
  type        = string
  default     = "http://localhost:8080"
}

variable "lambda_memory_size" {
  description = "Memory size for Lambda function"
  type        = number
  default     = 512
}

variable "lambda_timeout" {
  description = "Timeout for Lambda function"
  type        = number
  default     = 30
}