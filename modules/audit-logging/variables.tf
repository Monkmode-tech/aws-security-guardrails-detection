variable "name" {
  description = "Name prefix."
  type        = string
}

variable "aws_region" {
  description = "Home region of the trail."
  type        = string
}

variable "trail_name" {
  description = "CloudTrail trail name."
  type        = string
}

variable "kms_key_arn" {
  description = "Security KMS key for the trail, bucket and log group."
  type        = string
}

variable "critical_topic_arn" {
  description = "SNS topic for detections that need immediate attention."
  type        = string
}

variable "change_topic_arn" {
  description = "SNS topic for change-tracking detections reviewed daily."
  type        = string
}

variable "metric_namespace" {
  description = "CloudWatch namespace for detection metrics."
  type        = string
  default     = "SecurityBaseline/CloudTrail"
}

variable "log_retention_days" {
  description = "Retention of the trail's CloudWatch log group (searchable window)."
  type        = number
  default     = 90
}

variable "trail_retention_days" {
  description = "Days to keep trail files in S3 (moved to Glacier Instant Retrieval after 90)."
  type        = number
  default     = 365
}

variable "force_destroy_buckets" {
  description = "Allow destroy to delete a non-empty trail bucket (labs only)."
  type        = bool
  default     = true
}
