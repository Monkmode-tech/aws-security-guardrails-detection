output "function_names" {
  description = "Remediation function names."
  value       = { for k, f in aws_lambda_function.fn : k => f.function_name }
}

output "dead_letter_queues" {
  description = "Dead-letter queue URLs."
  value       = { for k, q in aws_sqs_queue.dlq : k => q.url }
}
