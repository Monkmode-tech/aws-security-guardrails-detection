"""Revoke security-group rules that expose sensitive ports to the whole internet.

Trigger : EventBridge rule on the CloudTrail events AuthorizeSecurityGroupIngress
          and ModifySecurityGroupRules.
Action  : Re-reads every ingress rule on the affected group (not just the one in
          the event), revokes any rule that opens a sensitive port - or all
          ports - to 0.0.0.0/0 or ::/0, tags the group, and alerts.
Opt-out : Groups tagged AllowPublicIngress=true are left alone (e.g. a public
          load balancer on 443 - though 80/443 are not "sensitive" by default).
Safety  : DRY_RUN=true reports what would be revoked without changing anything.

MITRE ATT&CK: T1133 External Remote Services, T1562.007 Disable or Modify Cloud Firewall.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
EXEMPT_TAG = "AllowPublicIngress"
DEFAULT_SENSITIVE_PORTS = "22,3389,3306,5432,1433,1521,6379,9200,11211,27017"


def sensitive_ports() -> set[int]:
    raw = os.environ.get("SENSITIVE_PORTS", DEFAULT_SENSITIVE_PORTS)
    return {int(p) for p in raw.split(",") if p.strip()}


def is_dry_run() -> bool:
    return os.environ.get("DRY_RUN", "false").lower() == "true"


def group_id_from_event(event: dict[str, Any]) -> str | None:
    """Extract the security group ID from either supported CloudTrail event."""
    params = (event.get("detail") or {}).get("requestParameters") or {}
    if params.get("groupId"):
        return params["groupId"]
    modify = params.get("ModifySecurityGroupRulesRequest") or {}
    return modify.get("GroupId")


def rule_is_violation(rule: dict[str, Any], ports: set[int]) -> bool:
    """True if an ingress rule opens a sensitive port (or everything) to the world."""
    if rule.get("IsEgress"):
        return False
    cidr = rule.get("CidrIpv4") or rule.get("CidrIpv6")
    if cidr not in WORLD_CIDRS:
        return False

    protocol = str(rule.get("IpProtocol", "")).lower()
    if protocol in ("-1", "all"):
        return True
    if protocol not in ("tcp", "udp", "6", "17"):
        return False  # ICMP and other protocols are out of scope

    low, high = rule.get("FromPort", -1), rule.get("ToPort", -1)
    if low == -1 or high == -1:
        return True
    return any(low <= port <= high for port in ports)


def find_violations(rules: Iterable[dict[str, Any]], ports: set[int]) -> list[dict[str, Any]]:
    return [r for r in rules if rule_is_violation(r, ports)]


def _tags(resource: dict[str, Any]) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in resource.get("Tags", [])}


def _all_rules(ec2: Any, group_id: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {"Filters": [{"Name": "group-id", "Values": [group_id]}]}
    while True:
        page = ec2.describe_security_group_rules(**kwargs)
        rules.extend(page.get("SecurityGroupRules", []))
        token = page.get("NextToken")
        if not token:
            return rules
        kwargs["NextToken"] = token


def _notify(sns: Any, subject: str, body: dict[str, Any]) -> None:
    topic = os.environ.get("ALERT_TOPIC_ARN")
    if topic:
        sns.publish(TopicArn=topic, Subject=subject[:100], Message=json.dumps(body, indent=2, default=str))


def handler(event: dict[str, Any], context: Any = None, ec2: Any = None, sns: Any = None) -> dict[str, Any]:
    if ec2 is None or sns is None:
        import boto3  # imported lazily so unit tests run without the AWS SDK

        ec2 = ec2 or boto3.client("ec2")
        sns = sns or boto3.client("sns")

    detail = event.get("detail") or {}
    group_id = group_id_from_event(event)
    if not group_id:
        LOG.info(json.dumps({"status": "skipped", "reason": "no security group in event"}))
        return {"status": "skipped", "reason": "no security group in event"}

    groups = ec2.describe_security_groups(GroupIds=[group_id]).get("SecurityGroups", [])
    if not groups:
        return {"status": "skipped", "reason": "security group no longer exists", "groupId": group_id}
    if _tags(groups[0]).get(EXEMPT_TAG, "").lower() == "true":
        return {"status": "skipped", "reason": f"group tagged {EXEMPT_TAG}=true", "groupId": group_id}

    violations = find_violations(_all_rules(ec2, group_id), sensitive_ports())
    if not violations:
        return {"status": "compliant", "groupId": group_id}

    rule_ids = [r["SecurityGroupRuleId"] for r in violations]
    dry_run = is_dry_run()
    if not dry_run:
        ec2.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=rule_ids)
        ec2.create_tags(
            Resources=[group_id],
            Tags=[{"Key": "SecurityAutoRemediated", "Value": datetime.now(UTC).isoformat(timespec="seconds")}],
        )

    result = {
        "status": "dry_run" if dry_run else "remediated",
        "action": "revoke world-open ingress on sensitive ports",
        "groupId": group_id,
        "revokedRuleIds": rule_ids,
        "rules": [
            {k: r.get(k) for k in ("IpProtocol", "FromPort", "ToPort", "CidrIpv4", "CidrIpv6")} for r in violations
        ],
        "actor": (detail.get("userIdentity") or {}).get("arn"),
        "sourceIp": detail.get("sourceIPAddress"),
        "eventName": detail.get("eventName"),
        "eventTime": detail.get("eventTime"),
    }
    LOG.info(json.dumps(result))
    _notify(sns, f"[AUTO-REMEDIATED] World-open ingress revoked on {group_id}", result)
    return result
