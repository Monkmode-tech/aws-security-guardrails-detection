variable "name" {
  description = "Name prefix."
  type        = string
}

variable "aws_region" {
  description = "Region the functions run in (remediations act on this region's resources)."
  type        = string
}

variable "kms_key_arn" {
  description = "Security KMS key (env vars, logs, encrypted SNS topic)."
  type        = string
}

variable "alert_topic_arn" {
  description = "SNS topic every remediation reports to."
  type        = string
}

variable "lambda_source_dir" {
  description = "Directory containing one folder per function with a handler.py."
  type        = string
}

variable "dry_run" {
  description = "Report what would be remediated without changing anything (use when first deploying)."
  type        = bool
  default     = false
}

variable "sensitive_ports" {
  description = "Ports that must never be open to 0.0.0.0/0 or ::/0."
  type        = list(number)
  default     = [22, 3389, 3306, 5432, 1433, 1521, 6379, 9200, 11211, 27017]
}

variable "isolation_min_severity" {
  description = "Minimum GuardDuty severity that triggers EC2 isolation (7 = High)."
  type        = number
  default     = 7
}

variable "log_retention_days" {
  description = "Retention for the functions' logs."
  type        = number
  default     = 90
}
