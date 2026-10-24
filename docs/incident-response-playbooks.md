# Incident response playbooks

Structured on the NIST SP 800-61 lifecycle: **Detect → Triage → Contain →
Eradicate → Recover → Learn.** Each playbook starts from the alert this repo
sends.

---

## P1 - Security group opened to the internet

**Alert:** `[AUTO-REMEDIATED] World-open ingress revoked on sg-...`

| Phase | Steps |
|-------|-------|
| Triage | Read `actor`, `sourceIp`, `eventTime` in the alert. Was it a person or automation? Expected change? |
| Contain | Already done: the rule was revoked within minutes. Confirm with `aws ec2 describe-security-group-rules --filters Name=group-id,Values=<sg>` |
| Eradicate | Check whether anything connected while it was open: VPC flow logs for the attached ENIs, filtered on the port and the open window. Run hunt query *world-open-security-group-ingress* for repeats by the same actor |
| Recover | If access was legitimately needed, provide it safely: SSM Session Manager or an allow-listed CIDR. Never re-open to `0.0.0.0/0` |
| Learn | Add a preventive control if this recurs (SCP or IaC policy check in CI) |

## P2 - S3 bucket made public

**Alert:** `[AUTO-REMEDIATED] Public access blocked on s3://...`

| Phase | Steps |
|-------|-------|
| Triage | Which bucket, what data class? Who made the change (`actor`)? |
| Contain | Already done at bucket level; the account-level block was on throughout. Check for public bucket policy text anyway: `aws s3api get-bucket-policy-status --bucket <b>` |
| Eradicate | Remove any public statements from the bucket policy and ACL grants to `AllUsers` / `AuthenticatedUsers` |
| Recover | If sharing was intended, use presigned URLs or CloudFront with origin access control |
| Learn | If the bucket held sensitive data, review S3 server access / CloudTrail data events for reads during the window |

## P3 - Compromised EC2 instance (GuardDuty high severity)

**Alert:** `[AUTO-CONTAINED] i-... isolated` or `[ACTION NEEDED] GuardDuty ... on i-...`

| Phase | Steps |
|-------|-------|
| Triage | Open the finding in GuardDuty: type, affected resource, remote IPs, first/last seen. Is the instance production? |
| Contain | If not auto-isolated: tag `AutoIsolate=true` and re-run, or manually attach a deny-all security group. **Security group changes do not cut existing tracked connections** - also add a deny NACL entry for the subnet if the finding shows an active session |
| Preserve | Forensic snapshots are taken before isolation (tag `SecurityFindingId`). Do not terminate the instance yet |
| Eradicate | Identify the entry point (exposed port? stolen credentials? vulnerable package?). Rotate any credentials the instance role or user data could reach |
| Recover | Rebuild from a known-good image via IaC, never "clean" the compromised host |
| Learn | Restore the previous security groups only on a rebuilt instance (`PreviousSecurityGroups` tag) |

## P4 - Root activity or tampering with logging

**Alert:** `root-account-usage`, `cloudtrail-config-changes`, `config-changes` or `kms-key-disable-or-delete` alarm

| Phase | Steps |
|-------|-------|
| Triage | Treat as hostile until proven otherwise. Run hunt query *logging-and-detection-tampering* and *console-logins* |
| Contain | Re-enable whatever was disabled (`aws cloudtrail start-logging`, restart the Config recorder, `aws kms cancel-key-deletion`). If root was used unexpectedly: change the root password, verify MFA, check for root access keys |
| Eradicate | Hunt query *new-iam-credentials-and-users* for persistence. Remove unknown users, keys and roles |
| Recover | Verify CloudTrail log integrity for the window: `aws cloudtrail validate-logs --trail-arn <arn> --start-time <t>` |
| Learn | In an AWS Organization, move these to preventive SCPs (deny `cloudtrail:StopLogging`, etc.) |
