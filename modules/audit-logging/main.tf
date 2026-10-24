###############################################################################
# Audit logging and detections-as-code
#
#   CloudTrail (all regions, global events, log-file validation, KMS)
#     -> S3 (versioned, TLS-only, lifecycle to Glacier)
#     -> CloudWatch Logs -> metric filters -> alarms -> SNS
#
# The 14 metric filters implement the CIS AWS Foundations Benchmark
# monitoring controls (AWS Security Hub controls CloudWatch.1 - CloudWatch.14).
# Each detection is tagged "critical" (page someone) or "change" (review daily)
# so tamper-type events never get lost among routine network changes.
###############################################################################

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_arn  = "arn:aws:cloudtrail:${var.aws_region}:${local.account_id}:trail/${var.trail_name}"

  detections = {
    "root-account-usage" = {
      control  = "CloudWatch.1"
      severity = "critical"
      pattern  = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    }
    "unauthorized-api-calls" = {
      control  = "CloudWatch.2"
      severity = "change"
      pattern  = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    }
    "console-login-without-mfa" = {
      control  = "CloudWatch.3"
      severity = "critical"
      pattern  = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    }
    "iam-policy-changes" = {
      control  = "CloudWatch.4"
      severity = "change"
      pattern  = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"
    }
    "cloudtrail-config-changes" = {
      control  = "CloudWatch.5"
      severity = "critical"
      pattern  = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    }
    "console-auth-failures" = {
      control  = "CloudWatch.6"
      severity = "change"
      pattern  = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
    }
    "kms-key-disable-or-delete" = {
      control  = "CloudWatch.7"
      severity = "critical"
      pattern  = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    }
    "s3-bucket-policy-changes" = {
      control  = "CloudWatch.8"
      severity = "change"
      pattern  = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
    }
    "config-changes" = {
      control  = "CloudWatch.9"
      severity = "critical"
      pattern  = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"
    }
    "security-group-changes" = {
      control  = "CloudWatch.10"
      severity = "change"
      pattern  = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
    }
    "nacl-changes" = {
      control  = "CloudWatch.11"
      severity = "change"
      pattern  = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
    }
    "network-gateway-changes" = {
      control  = "CloudWatch.12"
      severity = "change"
      pattern  = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
    }
    "route-table-changes" = {
      control  = "CloudWatch.13"
      severity = "change"
      pattern  = "{ ($.eventSource = ec2.amazonaws.com) && (($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable)) }"
    }
    "vpc-changes" = {
      control  = "CloudWatch.14"
      severity = "change"
      pattern  = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) }"
    }
  }

  topic_for = {
    critical = var.critical_topic_arn
    change   = var.change_topic_arn
  }
}

#------------------------------------------------------------------------------
# Trail bucket
#------------------------------------------------------------------------------
resource "aws_s3_bucket" "trail" {
  bucket        = "${var.name}-cloudtrail-${local.account_id}"
  force_destroy = var.force_destroy_buckets
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "archive-then-expire"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.trail_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

#------------------------------------------------------------------------------
# CloudWatch Logs delivery
#------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "trail" {
  name              = "/security/cloudtrail/${var.trail_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_iam_role" "cloudtrail_logs" {
  name               = "${var.name}-cloudtrail-to-logs"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}

data "aws_iam_policy_document" "cloudtrail_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name   = "write-trail-log-group"
  role   = aws_iam_role.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_logs.json
}

#------------------------------------------------------------------------------
# The trail
#------------------------------------------------------------------------------
resource "aws_cloudtrail" "this" {
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = var.kms_key_arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_logs.arn

  depends_on = [aws_s3_bucket_policy.trail, aws_iam_role_policy.cloudtrail_logs]
}

#------------------------------------------------------------------------------
# Detections: metric filter + alarm per CIS monitoring control
#------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each = local.detections

  name           = each.key
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.key
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each = local.detections

  alarm_name          = "${var.name}-${each.key}"
  alarm_description   = "${each.value.control} (${each.value.severity}): ${each.key} detected in CloudTrail. See docs/detection-catalog.md."
  namespace           = var.metric_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.detection[each.key].metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [local.topic_for[each.value.severity]]

  tags = {
    Control  = each.value.control
    Severity = each.value.severity
  }
}

#------------------------------------------------------------------------------
# Saved CloudWatch Logs Insights queries for threat hunting
#------------------------------------------------------------------------------
resource "aws_cloudwatch_query_definition" "console_logins" {
  name            = "${var.name}/hunt/console-logins"
  log_group_names = [aws_cloudwatch_log_group.trail.name]
  query_string    = <<-QUERY
    fields @timestamp, userIdentity.arn, sourceIPAddress, responseElements.ConsoleLogin, additionalEventData.MFAUsed, userAgent
    | filter eventName = "ConsoleLogin"
    | sort @timestamp desc
    | limit 200
  QUERY
}

resource "aws_cloudwatch_query_definition" "access_denied_by_principal" {
  name            = "${var.name}/hunt/access-denied-by-principal"
  log_group_names = [aws_cloudwatch_log_group.trail.name]
  query_string    = <<-QUERY
    filter errorCode like /AccessDenied|UnauthorizedOperation/
    | stats count(*) as denied by userIdentity.arn, eventSource, eventName
    | sort denied desc
    | limit 25
  QUERY
}

resource "aws_cloudwatch_query_definition" "world_open_ingress" {
  name            = "${var.name}/hunt/world-open-security-group-ingress"
  log_group_names = [aws_cloudwatch_log_group.trail.name]
  query_string    = <<-QUERY
    fields @timestamp, userIdentity.arn, sourceIPAddress, requestParameters.groupId
    | filter eventName in ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]
    | filter @message like "0.0.0.0/0" or @message like "::/0"
    | sort @timestamp desc
  QUERY
}

resource "aws_cloudwatch_query_definition" "new_credentials" {
  name            = "${var.name}/hunt/new-iam-credentials-and-users"
  log_group_names = [aws_cloudwatch_log_group.trail.name]
  query_string    = <<-QUERY
    fields @timestamp, eventName, userIdentity.arn, requestParameters.userName, sourceIPAddress
    | filter eventName in ["CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "AttachUserPolicy", "PutUserPolicy"]
    | sort @timestamp desc
  QUERY
}

resource "aws_cloudwatch_query_definition" "defense_evasion" {
  name            = "${var.name}/hunt/logging-and-detection-tampering"
  log_group_names = [aws_cloudwatch_log_group.trail.name]
  query_string    = <<-QUERY
    fields @timestamp, eventSource, eventName, userIdentity.arn, sourceIPAddress
    | filter eventName in ["StopLogging", "DeleteTrail", "UpdateTrail", "DeleteDetector", "DisassociateFromMasterAccount", "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DisableSecurityHub", "ScheduleKeyDeletion", "DisableKey"]
    | sort @timestamp desc
  QUERY
}
