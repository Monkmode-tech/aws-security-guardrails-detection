###############################################################################
# Attribute-based access control (ABAC) for patient records
#
# Implements the access model from the CLCS 605 "Cloud IAM and Data Security
# Design" (HIPAA patient-management system): job function and hospital ward
# decide access, enforced by ONE shared policy instead of a policy per role.
#
#   Role                  job-function   ward         Can do
#   physician-cardiology  physician      cardiology   read + write cardiology clinical records
#   nurse-cardiology      nurse          cardiology   read cardiology clinical records
#   nurse-oncology        nurse          oncology     read oncology clinical records only
#   billing-specialist    billing        -            read + write billing records only
#
# Records live in S3 under clinical/ or billing/ and carry object tags
# (data-class, ward). Access = principal tags match object tags.
# The bucket is encrypted with a dedicated "PHI" KMS key that only these
# roles can use for data - the account's admins can manage the key but cannot
# decrypt records with it.
###############################################################################

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  roles = {
    "physician-cardiology" = { job_function = "physician", ward = "cardiology" }
    "nurse-cardiology"     = { job_function = "nurse", ward = "cardiology" }
    "nurse-oncology"       = { job_function = "nurse", ward = "oncology" }
    "billing-specialist"   = { job_function = "billing", ward = "none" }
  }

  role_arns = [for r in keys(local.roles) : "arn:aws:iam::${local.account_id}:role/${var.name}-${r}"]
}

#------------------------------------------------------------------------------
# PHI encryption key: administrators manage it, only clinical roles use it
#------------------------------------------------------------------------------
data "aws_iam_policy_document" "phi_key" {
  statement {
    sid = "KeyAdministrationOnly"
    actions = [
      "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*",
      "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*",
      "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
      "kms:RotateKeyOnDemand",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "DataUseByRecordRolesViaS3Only"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = local.role_arns
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "phi" {
  description             = "${var.name} - protected health information"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.phi_key.json
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${var.name}-phi"
  target_key_id = aws_kms_key.phi.key_id
}

#------------------------------------------------------------------------------
# Records bucket
#------------------------------------------------------------------------------
resource "aws_s3_bucket" "records" {
  bucket        = "${var.name}-patient-records-${local.account_id}"
  force_destroy = var.force_destroy_bucket
}

resource "aws_s3_bucket_public_access_block" "records" {
  bucket                  = aws_s3_bucket.records.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "records" {
  bucket = aws_s3_bucket.records.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "records" {
  bucket = aws_s3_bucket.records.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "records" {
  bucket = aws_s3_bucket.records.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "records" {
  bucket = aws_s3_bucket.records.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "records_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.records.arn, "${aws_s3_bucket.records.arn}/*"]

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

  # Every record must carry a data classification tag.
  statement {
    sid       = "DenyUntaggedRecords"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.records.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:RequestObjectTag/data-class"
      values   = ["true"]
    }
  }
}

resource "aws_s3_bucket_policy" "records" {
  bucket = aws_s3_bucket.records.id
  policy = data.aws_iam_policy_document.records_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.records]
}

#------------------------------------------------------------------------------
# Roles (principal tags carry the attributes)
#------------------------------------------------------------------------------
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }

    dynamic "condition" {
      for_each = var.require_mfa ? [1] : []

      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "record_role" {
  for_each = local.roles

  name                 = "${var.name}-${each.key}"
  description          = "ABAC demo: ${each.value.job_function} (${each.value.ward})"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  max_session_duration = 3600

  tags = {
    "job-function" = each.value.job_function
    "ward"         = each.value.ward
  }
}

#------------------------------------------------------------------------------
# The single ABAC policy shared by every role
#------------------------------------------------------------------------------
data "aws_iam_policy_document" "abac" {
  # Clinicians read clinical records from their own ward.
  statement {
    sid       = "ReadClinicalRecordsInOwnWard"
    actions   = ["s3:GetObject", "s3:GetObjectTagging"]
    resources = ["${aws_s3_bucket.records.arn}/clinical/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/job-function"
      values   = ["physician", "nurse"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:ExistingObjectTag/data-class"
      values   = ["clinical"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:ExistingObjectTag/ward"
      values   = ["$${aws:PrincipalTag/ward}"]
    }
  }

  # Only physicians create clinical records, and only for their own ward.
  statement {
    sid       = "WriteClinicalRecordsInOwnWard"
    actions   = ["s3:PutObject", "s3:PutObjectTagging"]
    resources = ["${aws_s3_bucket.records.arn}/clinical/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/job-function"
      values   = ["physician"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:RequestObjectTag/data-class"
      values   = ["clinical"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:RequestObjectTag/ward"
      values   = ["$${aws:PrincipalTag/ward}"]
    }
  }

  # Billing staff work with billing records only - never clinical notes.
  statement {
    sid       = "BillingRecords"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:GetObjectTagging", "s3:PutObjectTagging"]
    resources = ["${aws_s3_bucket.records.arn}/billing/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/job-function"
      values   = ["billing"]
    }
  }

  statement {
    sid       = "ListClinicalPrefix"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.records.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/job-function"
      values   = ["physician", "nurse"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["clinical/", "clinical/*"]
    }
  }

  statement {
    sid       = "ListBillingPrefix"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.records.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/job-function"
      values   = ["billing"]
    }

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["billing/", "billing/*"]
    }
  }

  statement {
    sid       = "UsePhiKeyThroughS3"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.phi.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "abac" {
  name        = "${var.name}-patient-records-abac"
  description = "One attribute-based policy for every records role: principal tags must match object tags."
  policy      = data.aws_iam_policy_document.abac.json
}

resource "aws_iam_role_policy_attachment" "abac" {
  for_each = aws_iam_role.record_role

  role       = each.value.name
  policy_arn = aws_iam_policy.abac.arn
}
