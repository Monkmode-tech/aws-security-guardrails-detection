output "critical_topic_arn" {
  description = "SNS topic for critical security alerts."
  value       = aws_sns_topic.this["critical"].arn
}

output "change_topic_arn" {
  description = "SNS topic for change-tracking alerts."
  value       = aws_sns_topic.this["changes"].arn
}
