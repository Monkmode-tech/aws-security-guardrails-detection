###############################################################################
# Threat detection and posture management
#
#   GuardDuty          - threat detection from CloudTrail, VPC flow, DNS, S3,
#                        RDS login and Lambda network activity
#   AWS Config         - configuration history + managed rules (HIPAA-aligned set)
#   Security Hub       - AWS Foundational Security Best Practices + CIS benchmark
#   Access Analyzer    - finds resources shared outside the account
#   Account hardening  - S3 account-level public access block, EBS encryption by
#                        default, IAM password policy
###############################################################################

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  config_rules = {
    "s3-bucket-public-read-prohibited"         = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    "s3-bucket-server-side-encryption-enabled" = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
    "restricted-ssh"                           = "INCOMING_SSH_DISABLED"
    "root-account-mfa-enabled"                 = "ROOT_ACCOUNT_MFA_ENABLED"
    "iam-root-access-key-check"                = "IAM_ROOT_ACCESS_KEY_CHECK"
    "iam-user-mfa-enabled"                     = "IAM_USER_MFA_ENABLED"
    "encrypted-volumes"                        = "ENCRYPTED_VOLUMES"
    "rds-storage-encrypted"                    = "RDS_STORAGE_ENCRYPTED"
    "cloudtrail-enabled"                       = "CLOUD_TRAIL_ENABLED"
    "vpc-flow-logs-enabled"                    = "VPC_FLOW_LOGS_ENABLED"
  }

  # Resource types AWS Config records when record_all_resources = false.
  # Chosen to cover the managed rules above and the Security Hub controls that
  # matter for this portfolio, at a fraction of the cost of recording everything.
  config_resource_types = [
    "AWS::EC2::Instance",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::Volume",
    "AWS::EC2::VPC",
    "AWS::EC2::NetworkAcl",
    "AWS::EC2::Subnet",
    "AWS::S3::Bucket",
    "AWS::S3::AccountPublicAccessBlock",
    "AWS::IAM::User",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::KMS::Key",
    "AWS::CloudTrail::Trail",
    "AWS::RDS::DBInstance",
    "AWS::Lambda::Function",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
  ]
}

#------------------------------------------------------------------------------
# GuardDuty
#------------------------------------------------------------------------------
resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "this" {
  for_each = var.guardduty_features

  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  status      = each.value ? "ENABLED" : "DISABLED"
}

#------------------------------------------------------------------------------
# AWS Config
#------------------------------------------------------------------------------
resource "aws_s3_bucket" "config" {
  bucket        = "${var.name}-config-${local.account_id}"
  force_destroy = var.force_destroy_buckets
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    id     = "expire-config-history"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid       = "AWSConfigBucketPermissionsCheck"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.config.arn]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AWSConfigBucketDelivery"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/Config/*"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config.arn, "${aws_s3_bucket.config.arn}/*"]

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

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.config]
}

data "aws_iam_policy_document" "config_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.name}-aws-config"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

data "aws_iam_policy_document" "config_delivery" {
  statement {
    sid       = "DeliverToBucket"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "CheckBucket"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]
  }

  statement {
    sid       = "EncryptDeliveries"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  name   = "deliver-config-history"
  role   = aws_iam_role.config.id
  policy = data.aws_iam_policy_document.config_delivery.json
}

resource "aws_config_configuration_recorder" "this" {
  name     = "${var.name}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = var.config_record_all_resources
    include_global_resource_types = var.config_record_all_resources
    resource_types                = var.config_record_all_resources ? null : local.config_resource_types

    dynamic "recording_strategy" {
      for_each = var.config_record_all_resources ? [] : [1]

      content {
        use_only = "INCLUSION_BY_RESOURCE_TYPES"
      }
    }
  }

  recording_mode {
    recording_frequency = var.config_recording_frequency
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "${var.name}-delivery"
  s3_bucket_name = aws_s3_bucket.config.id
  s3_kms_key_arn = var.kms_key_arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.this, aws_s3_bucket_policy.config, aws_iam_role_policy.config_delivery]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_config_config_rule" "managed" {
  for_each = local.config_rules

  name = each.key

  source {
    owner             = "AWS"
    source_identifier = each.value
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

#------------------------------------------------------------------------------
# Security Hub
#------------------------------------------------------------------------------
resource "aws_securityhub_account" "this" {
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true

  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_securityhub_standards_subscription" "this" {
  for_each = toset(var.securityhub_standards)

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/${each.value}"

  depends_on = [aws_securityhub_account.this]
}

#------------------------------------------------------------------------------
# IAM Access Analyzer
#------------------------------------------------------------------------------
resource "aws_accessanalyzer_analyzer" "this" {
  analyzer_name = "${var.name}-external-access"
  type          = "ACCOUNT"
}

#------------------------------------------------------------------------------
# Account-level hardening
#------------------------------------------------------------------------------
resource "aws_s3_account_public_access_block" "this" {
  count = var.enable_account_s3_public_access_block ? 1 : 0

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
}
