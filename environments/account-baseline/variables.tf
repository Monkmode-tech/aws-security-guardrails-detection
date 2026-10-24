variable "aws_region" {
  description = "Home region for the baseline (trail, Config, Security Hub, remediations)."
  type        = string
  default     = "us-east-2"
}

variable "name" {
  description = "Name prefix for every resource."
  type        = string
  default     = "secbase"
}

variable "owner" {
  description = "Owner tag value."
  type        = string
  default     = "caleb-tetteh"
}

variable "critical_alert_emails" {
  description = "Emails for critical alerts (tampering, root use, high findings, remediations)."
  type        = list(string)
  default     = []
}

variable "change_alert_emails" {
  description = "Emails for change-tracking alerts (network and IAM changes)."
  type        = list(string)
  default     = []
}

variable "securityhub_alert_severities" {
  description = "Security Hub severities that page the critical channel."
  type        = list(string)
  default     = ["CRITICAL"]
}

variable "remediation_dry_run" {
  description = "true = remediations only report what they would do. Start true, review, then switch to false."
  type        = bool
  default     = false
}

variable "config_record_all_resources" {
  description = "Record every resource type in AWS Config (more complete, more expensive)."
  type        = bool
  default     = false
}

variable "enable_account_s3_public_access_block" {
  description = "Block public S3 access for the whole account."
  type        = bool
  default     = true
}
