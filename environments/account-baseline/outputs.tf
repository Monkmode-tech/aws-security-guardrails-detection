output "aws_region" {
  description = "Home region (used by scripts/)."
  value       = var.aws_region
}

output "trail_name" {
  description = "CloudTrail trail name."
  value       = local.trail_name
}

output "trail_log_group" {
  description = "Log group with every CloudTrail event; run the saved hunting queries against it."
  value       = module.audit_logging.trail_log_group
}

output "detection_alarms" {
  description = "Detection name to CloudWatch alarm."
  value       = module.audit_logging.detection_alarms
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID."
  value       = module.threat_detection.guardduty_detector_id
}

output "config_rule_names" {
  description = "AWS Config rules deployed."
  value       = module.threat_detection.config_rule_names
}

output "remediation_functions" {
  description = "Auto-remediation Lambda names."
  value       = module.auto_remediation.function_names
}

output "critical_topic_arn" {
  description = "Critical alerts topic."
  value       = module.alerting.critical_topic_arn
}

output "records_bucket" {
  description = "ABAC demo bucket."
  value       = module.abac_healthcare.records_bucket
}

output "record_role_arns" {
  description = "ABAC demo roles."
  value       = module.abac_healthcare.role_arns
}
