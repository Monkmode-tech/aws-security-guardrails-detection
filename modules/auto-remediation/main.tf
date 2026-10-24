###############################################################################
# Auto-remediation
#
# EventBridge -> Lambda for three high-confidence, low-blast-radius fixes:
#   revoke_public_ingress - world-open SSH/RDP/DB ports are revoked in seconds
#   block_public_s3       - bucket-level Block Public Access is re-applied
#   isolate_ec2           - GuardDuty high-severity finding -> quarantine + snapshot
#                           (opt-in per instance via the AutoIsolate=true tag)
#
# Each function has its own least-privilege role, a dead-letter queue for
# failed invocations, X-Ray tracing, KMS-encrypted environment variables, and
# an alarm on errors.
###############################################################################

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = var.aws_region

  functions = {
    revoke_public_ingress = {
      description = "Revoke security group rules that open sensitive ports to the internet"
      environment = tomap({ SENSITIVE_PORTS = join(",", var.sensitive_ports) })
      event_pattern = jsonencode({
        source        = ["aws.ec2"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ec2.amazonaws.com"]
          eventName   = ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]
        }
      })
    }
    block_public_s3 = {
      description = "Re-apply S3 Block Public Access when it is weakened on a bucket"
      environment = tomap({})
      event_pattern = jsonencode({
        source        = ["aws.s3"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["s3.amazonaws.com"]
          eventName   = ["PutBucketAcl", "PutBucketPolicy", "PutPublicAccessBlock", "DeletePublicAccessBlock"]
        }
      })
    }
    isolate_ec2 = {
      description = "Quarantine and snapshot EC2 instances with high-severity GuardDuty findings"
      environment = tomap({ MIN_SEVERITY = tostring(var.isolation_min_severity) })
      event_pattern = jsonencode({
        source        = ["aws.guardduty"]
        "detail-type" = ["GuardDuty Finding"]
        detail = {
          severity = [{ numeric = [">=", var.isolation_min_severity] }]
          resource = { resourceType = ["Instance"] }
        }
      })
    }
  }
}

#------------------------------------------------------------------------------
# Function-specific permissions
#------------------------------------------------------------------------------
data "aws_iam_policy_document" "revoke_public_ingress" {
  statement {
    sid       = "ReadSecurityGroups"
    actions   = ["ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules"]
    resources = ["*"] # Describe* actions do not support resource-level permissions
  }

  statement {
    sid       = "RevokeAndTag"
    actions   = ["ec2:RevokeSecurityGroupIngress", "ec2:CreateTags"]
    resources = ["arn:aws:ec2:${local.region}:${local.account_id}:security-group/*"]
  }
}

data "aws_iam_policy_document" "block_public_s3" {
  statement {
    sid = "ManageBucketPublicAccess"
    actions = [
      "s3:GetBucketTagging",
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
    ]
    resources = ["arn:aws:s3:::*"]
  }
}

data "aws_iam_policy_document" "isolate_ec2" {
  statement {
    sid       = "Describe"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"]
    resources = ["*"]
  }

  statement {
    sid       = "CreateQuarantineGroup"
    actions   = ["ec2:CreateSecurityGroup", "ec2:RevokeSecurityGroupEgress", "ec2:CreateTags"]
    resources = ["arn:aws:ec2:${local.region}:${local.account_id}:security-group/*", "arn:aws:ec2:${local.region}:${local.account_id}:vpc/*"]
  }

  statement {
    sid       = "ForensicSnapshots"
    actions   = ["ec2:CreateSnapshot", "ec2:CreateTags"]
    resources = ["arn:aws:ec2:${local.region}:${local.account_id}:volume/*", "arn:aws:ec2:${local.region}::snapshot/*"]
  }

  # The opt-in tag is enforced here too: even a bug in the function cannot
  # change the network or tags of an instance that was not opted in.
  statement {
    sid       = "IsolateOptedInInstancesOnly"
    actions   = ["ec2:ModifyInstanceAttribute", "ec2:CreateTags"]
    resources = ["arn:aws:ec2:${local.region}:${local.account_id}:instance/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/AutoIsolate"
      values   = ["true"]
    }
  }

  statement {
    sid       = "AttachQuarantineGroup"
    actions   = ["ec2:ModifyInstanceAttribute"]
    resources = ["arn:aws:ec2:${local.region}:${local.account_id}:security-group/*"]
  }
}

locals {
  function_policies = {
    revoke_public_ingress = data.aws_iam_policy_document.revoke_public_ingress.json
    block_public_s3       = data.aws_iam_policy_document.block_public_s3.json
    isolate_ec2           = data.aws_iam_policy_document.isolate_ec2.json
  }
}

#------------------------------------------------------------------------------
# Shared building blocks, one set per function
#------------------------------------------------------------------------------
data "archive_file" "fn" {
  for_each = local.functions

  type        = "zip"
  source_file = "${var.lambda_source_dir}/${each.key}/handler.py"
  output_path = "${path.root}/.build/${each.key}.zip"
}

resource "aws_sqs_queue" "dlq" {
  for_each = local.functions

  name                      = "${var.name}-${replace(each.key, "_", "-")}-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_cloudwatch_log_group" "fn" {
  for_each = local.functions

  name              = "/aws/lambda/${var.name}-${replace(each.key, "_", "-")}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "fn" {
  for_each = local.functions

  name               = "${var.name}-${replace(each.key, "_", "-")}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "common" {
  for_each = local.functions

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.fn[each.key].arn}:*"]
  }

  statement {
    sid       = "PublishAlert"
    actions   = ["sns:Publish"]
    resources = [var.alert_topic_arn]
  }

  # Publishing to a KMS-encrypted topic and reading encrypted env vars.
  statement {
    sid       = "UseSecurityKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }

  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq[each.key].arn]
  }

  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "common" {
  for_each = local.functions

  name   = "common"
  role   = aws_iam_role.fn[each.key].id
  policy = data.aws_iam_policy_document.common[each.key].json
}

resource "aws_iam_role_policy" "specific" {
  for_each = local.functions

  name   = "remediation"
  role   = aws_iam_role.fn[each.key].id
  policy = local.function_policies[each.key]
}

resource "aws_lambda_function" "fn" {
  for_each = local.functions
  # checkov:skip=CKV_AWS_117: Calls only public AWS APIs; a VPC would add NAT cost without reducing exposure
  # checkov:skip=CKV_AWS_115: Reserved concurrency can fail on new accounts with a 10-execution limit
  # checkov:skip=CKV_AWS_272: Code signing is out of scope; code is reviewed and deployed from this repo by Terraform

  function_name    = "${var.name}-${replace(each.key, "_", "-")}"
  description      = each.value.description
  role             = aws_iam_role.fn[each.key].arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.fn[each.key].output_path
  source_code_hash = data.archive_file.fn[each.key].output_base64sha256
  timeout          = 60
  memory_size      = 256
  kms_key_arn      = var.kms_key_arn

  environment {
    variables = merge(each.value.environment, {
      ALERT_TOPIC_ARN = var.alert_topic_arn
      DRY_RUN         = tostring(var.dry_run)
    })
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq[each.key].arn
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_iam_role_policy.common, aws_cloudwatch_log_group.fn]
}

#------------------------------------------------------------------------------
# Triggers
#------------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "fn" {
  for_each = local.functions

  name          = "${var.name}-${replace(each.key, "_", "-")}"
  description   = each.value.description
  event_pattern = each.value.event_pattern
}

resource "aws_cloudwatch_event_target" "fn" {
  for_each = local.functions

  rule = aws_cloudwatch_event_rule.fn[each.key].name
  arn  = aws_lambda_function.fn[each.key].arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 4
  }
}

resource "aws_lambda_permission" "events" {
  for_each = local.functions

  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.fn[each.key].arn
}

#------------------------------------------------------------------------------
# Watch the watchers: alarm if a remediation fails
#------------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "errors" {
  for_each = local.functions

  alarm_name          = "${var.name}-${replace(each.key, "_", "-")}-errors"
  alarm_description   = "Auto-remediation ${each.key} failed - the issue it was fixing may still be open."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.fn[each.key].function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alert_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  for_each = local.functions

  alarm_name          = "${var.name}-${replace(each.key, "_", "-")}-dlq"
  alarm_description   = "Events for ${each.key} landed in the dead-letter queue after all retries."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq[each.key].name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alert_topic_arn]
}
