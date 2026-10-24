# ADR 0001: Automate only reversible, low-blast-radius fixes

**Status:** Accepted

## Context

Auto-remediation shrinks exposure from hours to minutes, but a wrong automatic
action can cause an outage. The risk of each action is different.

## Decision

| Action | Automatic? | Why |
|--------|------------|-----|
| Revoke world-open ingress on sensitive ports | Yes | Nothing legitimate needs SSH/RDP/DB ports open to the internet; easy to re-add a scoped rule |
| Re-apply S3 Block Public Access | Yes | Account-level block already enforces it; public sharing has better patterns |
| Isolate an EC2 instance | **Opt-in** (`AutoIsolate=true`) | Can take a service down; snapshot first, and a human decides for untagged instances |
| Delete or disable IAM users/keys | No | Too easy to lock out administrators; alert and follow playbook P4 |

Every function also supports `DRY_RUN`, ships with an exemption tag, reports
every action to the critical channel, and has an error alarm and dead-letter queue.

## Consequences

- Fast, safe containment for the most common misconfigurations.
- The opt-in condition is enforced in the Lambda's IAM policy as well as its
  code, so a bug cannot isolate an instance that was never opted in.
