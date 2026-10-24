###############################################################################
# Alerting
#
# Two channels, to keep high-signal alerts from drowning in routine change:
#   critical - tampering, root use, high-severity findings, auto-remediations
#   changes  - network/IAM change tracking, medium findings (daily review)
#
# EventBridge routes GuardDuty, Security Hub and IAM Access Analyzer findings
# to the right channel with a human-readable message.
###############################################################################

data "aws_caller_identity" "current" {}

locals {
  topics = {
    critical = var.critical_emails
    changes  = var.change_emails
  }

  topic_subscriptions = merge([
    for topic, emails in local.topics : {
      for email in emails : "${topic}:${email}" => { topic = topic, email = email }
    }
  ]...)
}

resource "aws_sns_topic" "this" {
  for_each = local.topics

  name              = "${var.name}-${each.key}"
  kms_master_key_id = var.kms_key_arn
}

data "aws_iam_policy_document" "topic" {
  for_each = local.topics

  statement {
    sid       = "OwnerAccountFullAccess"
    actions   = ["sns:Publish", "sns:Subscribe", "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:ListSubscriptionsByTopic"]
    resources = [aws_sns_topic.this[each.key].arn]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowAlarmsAndEventBridgeFromThisAccount"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.this[each.key].arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "this" {
  for_each = local.topics

  arn    = aws_sns_topic.this[each.key].arn
  policy = data.aws_iam_policy_document.topic[each.key].json
}

resource "aws_sns_topic_subscription" "email" {
  for_each = local.topic_subscriptions

  topic_arn = aws_sns_topic.this[each.value.topic].arn
  protocol  = "email"
  endpoint  = each.value.email
}

#------------------------------------------------------------------------------
# GuardDuty findings
#------------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "${var.name}-guardduty-high"
  description = "GuardDuty findings with severity >= 7 (High/Critical)"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail        = { severity = [{ numeric = [">=", 7] }] }
  })
}

resource "aws_cloudwatch_event_rule" "guardduty_medium" {
  name        = "${var.name}-guardduty-medium"
  description = "GuardDuty findings with severity 4 to < 7 (Medium)"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail        = { severity = [{ numeric = [">=", 4, "<", 7] }] }
  })
}

locals {
  guardduty_input_paths = {
    severity = "$.detail.severity"
    type     = "$.detail.type"
    title    = "$.detail.title"
    account  = "$.account"
    region   = "$.region"
    id       = "$.detail.id"
  }
  guardduty_template = "\"GuardDuty finding (severity <severity>): <title> | Type: <type> | Account <account>, <region> | Finding ID <id>\""
}

resource "aws_cloudwatch_event_target" "guardduty_high" {
  rule = aws_cloudwatch_event_rule.guardduty_high.name
  arn  = aws_sns_topic.this["critical"].arn

  input_transformer {
    input_paths    = local.guardduty_input_paths
    input_template = local.guardduty_template
  }
}

resource "aws_cloudwatch_event_target" "guardduty_medium" {
  rule = aws_cloudwatch_event_rule.guardduty_medium.name
  arn  = aws_sns_topic.this["changes"].arn

  input_transformer {
    input_paths    = local.guardduty_input_paths
    input_template = local.guardduty_template
  }
}

#------------------------------------------------------------------------------
# Security Hub findings (new, active, failed, at the configured severities)
#------------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "securityhub" {
  name        = "${var.name}-securityhub-findings"
  description = "New, active Security Hub findings at ${join("/", var.securityhub_alert_severities)} severity"

  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = var.securityhub_alert_severities }
        Workflow    = { Status = ["NEW"] }
        RecordState = ["ACTIVE"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub" {
  rule = aws_cloudwatch_event_rule.securityhub.name
  arn  = aws_sns_topic.this["critical"].arn

  input_transformer {
    input_paths = {
      severity = "$.detail.findings[0].Severity.Label"
      title    = "$.detail.findings[0].Title"
      resource = "$.detail.findings[0].Resources[0].Id"
      control  = "$.detail.findings[0].Compliance.SecurityControlId"
    }
    input_template = "\"Security Hub <severity>: <title> | Control <control> | Resource <resource>\""
  }
}

#------------------------------------------------------------------------------
# IAM Access Analyzer: something became reachable from outside the account
#------------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "access_analyzer" {
  name        = "${var.name}-external-access"
  description = "IAM Access Analyzer found a resource shared outside the account"

  event_pattern = jsonencode({
    source        = ["aws.access-analyzer"]
    "detail-type" = ["Access Analyzer Finding"]
    detail        = { status = ["ACTIVE"] }
  })
}

resource "aws_cloudwatch_event_target" "access_analyzer" {
  rule = aws_cloudwatch_event_rule.access_analyzer.name
  arn  = aws_sns_topic.this["critical"].arn

  input_transformer {
    input_paths = {
      resource = "$.detail.resource"
      type     = "$.detail.resourceType"
      action   = "$.detail.action"
    }
    input_template = "\"External access detected: <type> <resource> is shared outside the account (actions: <action>). Review in IAM Access Analyzer.\""
  }
}
