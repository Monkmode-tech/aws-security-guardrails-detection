output "guardduty_detector_id" {
  description = "GuardDuty detector ID (used by the sample-findings simulation)."
  value       = aws_guardduty_detector.this.id
}

output "config_recorder_name" {
  description = "AWS Config recorder name."
  value       = aws_config_configuration_recorder.this.name
}

output "config_rule_names" {
  description = "Managed AWS Config rules deployed."
  value       = [for r in aws_config_config_rule.managed : r.name]
}

output "securityhub_standards" {
  description = "Enabled Security Hub standard ARNs."
  value       = [for s in aws_securityhub_standards_subscription.this : s.standards_arn]
}

output "access_analyzer_arn" {
  description = "IAM Access Analyzer ARN."
  value       = aws_accessanalyzer_analyzer.this.arn
}
