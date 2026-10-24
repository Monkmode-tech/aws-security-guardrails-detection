variable "name" {
  description = "Name prefix for the bucket, key and roles."
  type        = string
}

variable "aws_region" {
  description = "Region of the records bucket (used in kms:ViaService)."
  type        = string
}

variable "require_mfa" {
  description = "Require MFA to assume the record roles. IAM Identity Center sessions do not carry the MFA flag, so leave false when testing with SSO."
  type        = bool
  default     = false
}

variable "force_destroy_bucket" {
  description = "Allow destroy to delete a non-empty records bucket (demo data only)."
  type        = bool
  default     = true
}
