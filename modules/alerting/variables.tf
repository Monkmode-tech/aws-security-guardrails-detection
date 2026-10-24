variable "name" {
  description = "Name prefix."
  type        = string
}

variable "kms_key_arn" {
  description = "Security KMS key for the SNS topics."
  type        = string
}

variable "critical_emails" {
  description = "Emails subscribed to the critical channel (each must confirm the AWS subscription email)."
  type        = list(string)
  default     = []
}

variable "change_emails" {
  description = "Emails subscribed to the change-tracking channel."
  type        = list(string)
  default     = []
}

variable "securityhub_alert_severities" {
  description = "Security Hub severity labels that raise a critical alert. Start with CRITICAL to avoid the initial-scan burst."
  type        = list(string)
  default     = ["CRITICAL"]

  validation {
    condition     = alltrue([for s in var.securityhub_alert_severities : contains(["CRITICAL", "HIGH", "MEDIUM", "LOW"], s)])
    error_message = "Allowed values: CRITICAL, HIGH, MEDIUM, LOW."
  }
}
