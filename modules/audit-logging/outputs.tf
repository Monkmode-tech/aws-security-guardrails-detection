output "trail_arn" {
  description = "CloudTrail trail ARN."
  value       = aws_cloudtrail.this.arn
}

output "trail_bucket" {
  description = "S3 bucket holding trail files."
  value       = aws_s3_bucket.trail.id
}

output "trail_log_group" {
  description = "CloudWatch log group receiving trail events."
  value       = aws_cloudwatch_log_group.trail.name
}

output "detection_alarms" {
  description = "Map of detection name to alarm name."
  value       = { for k, a in aws_cloudwatch_metric_alarm.detection : k => a.alarm_name }
}
