output "records_bucket" {
  description = "Bucket holding the demo patient records."
  value       = aws_s3_bucket.records.id
}

output "role_arns" {
  description = "Map of record role name to ARN (used by scripts/validate-abac.sh)."
  value       = { for k, r in aws_iam_role.record_role : k => r.arn }
}

output "phi_key_arn" {
  description = "KMS key protecting the records."
  value       = aws_kms_key.phi.arn
}
