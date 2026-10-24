###############################################################################
# Account security baseline
#
#   audit-logging     CloudTrail + 14 CIS detections + hunting queries
#   threat-detection  GuardDuty, Config + rules, Security Hub, Access Analyzer,
#                     account hardening
#   alerting          critical / change channels + finding routing
#   auto-remediation  3 event-driven Lambdas
#   abac-healthcare   attribute-based access to patient records
###############################################################################

locals {
  name       = var.name
  trail_name = "${var.name}-trail"
}

module "kms" {
  source = "../../modules/kms"

  name       = local.name
  aws_region = var.aws_region
  trail_name = local.trail_name
}

module "alerting" {
  source = "../../modules/alerting"

  name                         = local.name
  kms_key_arn                  = module.kms.key_arn
  critical_emails              = var.critical_alert_emails
  change_emails                = var.change_alert_emails
  securityhub_alert_severities = var.securityhub_alert_severities
}

module "audit_logging" {
  source = "../../modules/audit-logging"

  name               = local.name
  aws_region         = var.aws_region
  trail_name         = local.trail_name
  kms_key_arn        = module.kms.key_arn
  critical_topic_arn = module.alerting.critical_topic_arn
  change_topic_arn   = module.alerting.change_topic_arn
}

module "threat_detection" {
  source = "../../modules/threat-detection"

  name                                  = local.name
  aws_region                            = var.aws_region
  kms_key_arn                           = module.kms.key_arn
  config_record_all_resources           = var.config_record_all_resources
  enable_account_s3_public_access_block = var.enable_account_s3_public_access_block
}

module "auto_remediation" {
  source = "../../modules/auto-remediation"

  name              = local.name
  aws_region        = var.aws_region
  kms_key_arn       = module.kms.key_arn
  alert_topic_arn   = module.alerting.critical_topic_arn
  lambda_source_dir = "${path.root}/../../lambdas"
  dry_run           = var.remediation_dry_run

  # Remediations react to CloudTrail events, so the trail must exist first.
  depends_on = [module.audit_logging]
}

module "abac_healthcare" {
  source = "../../modules/abac-healthcare"

  name       = local.name
  aws_region = var.aws_region
}
