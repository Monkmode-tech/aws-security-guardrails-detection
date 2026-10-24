variable "name" {
  description = "Name prefix."
  type        = string
}

variable "aws_region" {
  description = "Region where Security Hub standards are enabled."
  type        = string
}

variable "kms_key_arn" {
  description = "Security KMS key for the Config delivery bucket."
  type        = string
}

variable "guardduty_features" {
  description = "GuardDuty protection plans to enable. Paid plans that need agents or scanning are off by default."
  type        = map(bool)
  default = {
    S3_DATA_EVENTS         = true
    RDS_LOGIN_EVENTS       = true
    LAMBDA_NETWORK_LOGS    = true
    EKS_AUDIT_LOGS         = false
    EBS_MALWARE_PROTECTION = false
  }
}

variable "config_record_all_resources" {
  description = "Record every supported resource type (more complete, more expensive) instead of the curated list."
  type        = bool
  default     = false
}

variable "config_recording_frequency" {
  description = "CONTINUOUS (real-time) or DAILY (cheaper) configuration recording."
  type        = string
  default     = "CONTINUOUS"

  validation {
    condition     = contains(["CONTINUOUS", "DAILY"], var.config_recording_frequency)
    error_message = "config_recording_frequency must be CONTINUOUS or DAILY."
  }
}

variable "securityhub_standards" {
  description = "Security Hub standards to enable, as the path after 'standards/' in the standard ARN."
  type        = list(string)
  default = [
    "aws-foundational-security-best-practices/v/1.0.0",
    "cis-aws-foundations-benchmark/v/3.0.0",
  ]
}

variable "enable_account_s3_public_access_block" {
  description = "Block public S3 access for the whole account. Turn off only if the account must host a public bucket."
  type        = bool
  default     = true
}

variable "force_destroy_buckets" {
  description = "Allow destroy to delete a non-empty Config bucket (labs only)."
  type        = bool
  default     = true
}
