variable "name" {
  description = "Name prefix; the alias becomes alias/<name>."
  type        = string
}

variable "aws_region" {
  description = "Home region of the trail and log groups."
  type        = string
}

variable "trail_name" {
  description = "Name of the CloudTrail trail allowed to use the key."
  type        = string
}

variable "deletion_window_in_days" {
  description = "Waiting period before a scheduled key deletion completes (7-30)."
  type        = number
  default     = 7
}
