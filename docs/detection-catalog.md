# Detection catalog

Every detection, where its signal comes from, what it maps to, and what happens
when it fires. "Critical" alerts go to the critical SNS channel; "change" alerts
go to the daily-review channel.

## CloudTrail metric-filter detections

| # | Detection | Security Hub / CIS | MITRE ATT&CK | Channel | Response |
|---|-----------|--------------------|--------------|---------|----------|
| 1 | Root account used | CloudWatch.1 | T1078.004 Valid Accounts: Cloud Accounts | critical | Playbook P4 |
| 2 | Unauthorized API calls | CloudWatch.2 | Discovery (TA0007) | change | Hunt query "access denied by principal" |
| 3 | Console sign-in without MFA | CloudWatch.3 | T1078.004 | critical | Confirm with user; enforce MFA |
| 4 | IAM policy changes | CloudWatch.4 | T1098 Account Manipulation | change | Review change against tickets/PRs |
| 5 | CloudTrail configuration changed | CloudWatch.5 | T1562.008 Disable or Modify Cloud Logs | critical | Playbook P4; simulation 04 |
| 6 | Console authentication failures | CloudWatch.6 | T1110 Brute Force | change | Hunt query "console logins" |
| 7 | KMS key disabled or scheduled for deletion | CloudWatch.7 | T1485 Data Destruction | critical | Cancel deletion; investigate actor |
| 8 | S3 bucket policy / ACL changes | CloudWatch.8 | T1530 Data from Cloud Storage | change | Auto-remediation R2 if made public |
| 9 | AWS Config changes | CloudWatch.9 | T1562 Impair Defenses | critical | Restart recorder; investigate actor |
| 10 | Security group changes | CloudWatch.10 | T1562.007 Disable or Modify Cloud Firewall | change | Auto-remediation R1 if world-open |
| 11 | Network ACL changes | CloudWatch.11 | T1562.007 | change | Review |
| 12 | Network gateway changes | CloudWatch.12 | Change tracking | change | Review |
| 13 | Route table changes | CloudWatch.13 | Change tracking | change | Review |
| 14 | VPC changes | CloudWatch.14 | Change tracking | change | Review |

## Event-driven detections and automatic responses

| ID | Trigger | ATT&CK | Automatic action | Verified by |
|----|---------|--------|------------------|-------------|
| R1 | `AuthorizeSecurityGroupIngress` / `ModifySecurityGroupRules` opening 22, 3389, 3306, 5432, 1433, 1521, 6379, 9200, 11211 or 27017 (or all ports) to `0.0.0.0/0` / `::/0` | T1133, T1562.007 | Revoke the rule(s), tag the group, alert | Unit tests + `simulate/01-open-ssh-to-world.sh` |
| R2 | `PutBucketAcl`, `PutBucketPolicy`, `PutPublicAccessBlock`, `DeletePublicAccessBlock` leaving Block Public Access incomplete | T1530 | Re-apply all four settings, alert | Unit tests + `simulate/02-make-bucket-public.sh` |
| R3 | GuardDuty finding, severity >= 7, resource = EC2 instance | T1496 and others | Snapshot volumes, move to deny-all quarantine group, tag, alert (opt-in `AutoIsolate=true`) | Unit tests + `simulate/03-guardduty-high-finding.sh` |
| A1 | GuardDuty severity >= 7 | varies | Critical alert | `simulate/03` |
| A2 | GuardDuty severity 4 to < 7 | varies | Change-channel alert | GuardDuty sample findings |
| A3 | Security Hub finding: new, active, severity in `securityhub_alert_severities` | varies | Critical alert | Security Hub console |
| A4 | IAM Access Analyzer: resource shared outside the account | T1537 Transfer Data to Cloud Account | Critical alert | Share a test bucket with another account |

## Posture rules (AWS Config, HIPAA-aligned selection)

| Rule | Why it matters for patient data |
|------|---------------------------------|
| s3-bucket-public-read-prohibited | No public exposure of records |
| s3-bucket-server-side-encryption-enabled | Encryption at rest |
| restricted-ssh | No internet-facing admin access |
| root-account-mfa-enabled | Protect the most privileged identity |
| iam-root-access-key-check | Root must never have access keys |
| iam-user-mfa-enabled | Strong authentication for every user |
| encrypted-volumes | Encryption at rest on servers |
| rds-storage-encrypted | Encryption at rest for databases |
| cloudtrail-enabled | Audit logging (HIPAA audit controls) |
| vpc-flow-logs-enabled | Network activity records |

Security Hub adds the full AWS Foundational Security Best Practices and CIS
AWS Foundations Benchmark v3.0 control sets on top of these.

## Hunting queries (CloudWatch Logs Insights)

Saved under `<prefix>/hunt/` in the console:

| Query | Use it to |
|-------|-----------|
| console-logins | See every sign-in with source IP, MFA use and outcome |
| access-denied-by-principal | Find who is probing for permissions they don't have |
| world-open-security-group-ingress | List every attempt to open a group to the internet |
| new-iam-credentials-and-users | Spot persistence: new users, keys, login profiles, inline policies |
| logging-and-detection-tampering | Find attempts to stop CloudTrail, GuardDuty, Config, Security Hub or KMS |
