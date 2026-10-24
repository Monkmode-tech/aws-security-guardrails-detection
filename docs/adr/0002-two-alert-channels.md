# ADR 0002: Two alert channels to fight alert fatigue

**Status:** Accepted

## Context

The CIS monitoring controls include detections for every security group, route
table and VPC change. Deploying any of the other portfolio projects triggers
dozens of them. If those share a channel with "CloudTrail was stopped," the
important alert gets ignored.

## Decision

- **critical**: root use, sign-in without MFA, CloudTrail/Config/KMS tampering,
  GuardDuty severity >= 7, Security Hub CRITICAL, external access, and every
  auto-remediation report. This channel should be silent on a normal day.
- **changes**: IAM policy, network, S3 policy and authorization-failure
  detections, plus GuardDuty medium findings. Reviewed once a day.

## Consequences

- An email on the critical channel always deserves attention.
- Change tracking still exists and is searchable; it just doesn't interrupt.
- Security Hub starts at CRITICAL only, because a new account's first scan
  produces a burst of HIGH findings; widen it once the backlog is fixed.
