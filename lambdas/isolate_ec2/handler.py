"""Quarantine an EC2 instance when GuardDuty reports a high-severity finding.

Trigger : EventBridge rule on GuardDuty findings with severity >= 7 whose
          resource is an EC2 instance.
Action  : 1. Swap the instance's security groups for a "quarantine" group with
             no inbound or outbound rules (created per VPC on first use).
          2. Snapshot every attached EBS volume for forensics.
          3. Tag the instance with the finding ID and time, then alert.
Opt-in  : Only instances tagged AutoIsolate=true are isolated (the Lambda's IAM
          policy enforces the same condition). Others produce an alert that says
          what would have happened - isolation is disruptive, so a human decides.
Safety  : DRY_RUN=true reports the plan without changing anything.

Note: changing security groups does not cut already-tracked connections. The
playbook (docs/incident-response-playbooks.md) covers the follow-up NACL step.

Response phase (NIST SP 800-61): Containment, with evidence preserved first.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

OPT_IN_TAG = "AutoIsolate"
QUARANTINE_GROUP_NAME = "security-quarantine"


def is_dry_run() -> bool:
    return os.environ.get("DRY_RUN", "false").lower() == "true"


def min_severity() -> float:
    return float(os.environ.get("MIN_SEVERITY", "7"))


def error_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def parse_finding(event: dict[str, Any]) -> dict[str, Any]:
    detail = event.get("detail") or {}
    resource = detail.get("resource") or {}
    return {
        "id": detail.get("id"),
        "type": detail.get("type"),
        "severity": float(detail.get("severity", 0)),
        "title": detail.get("title"),
        "resourceType": resource.get("resourceType"),
        "instanceId": (resource.get("instanceDetails") or {}).get("instanceId"),
    }


def quarantine_group(ec2: Any, vpc_id: str) -> str:
    """Return the quarantine group for the VPC, creating it (deny-all) if needed."""
    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [QUARANTINE_GROUP_NAME]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    ).get("SecurityGroups", [])
    if existing:
        return existing[0]["GroupId"]

    group_id = ec2.create_security_group(
        GroupName=QUARANTINE_GROUP_NAME,
        Description="Incident response quarantine - no inbound or outbound traffic",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Purpose", "Value": "quarantine"}]}],
    )["GroupId"]
    # New groups allow all egress by default; remove it so the group is deny-all.
    ec2.revoke_security_group_egress(
        GroupId=group_id, IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    )
    return group_id


def _notify(sns: Any, subject: str, body: dict[str, Any]) -> None:
    topic = os.environ.get("ALERT_TOPIC_ARN")
    if topic:
        sns.publish(TopicArn=topic, Subject=subject[:100], Message=json.dumps(body, indent=2, default=str))


def handler(event: dict[str, Any], context: Any = None, ec2: Any = None, sns: Any = None) -> dict[str, Any]:
    if ec2 is None or sns is None:
        import boto3

        ec2 = ec2 or boto3.client("ec2")
        sns = sns or boto3.client("sns")

    finding = parse_finding(event)
    if finding["resourceType"] != "Instance" or not finding["instanceId"]:
        return {"status": "skipped", "reason": "finding is not about an EC2 instance", "finding": finding}
    if finding["severity"] < min_severity():
        return {"status": "skipped", "reason": "below severity threshold", "finding": finding}

    instance_id = finding["instanceId"]
    try:
        reservations = ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
            result = {"status": "not_found", "finding": finding,
                      "note": "Instance does not exist - expected for GuardDuty sample findings."}
            _notify(sns, f"[GuardDuty] {finding['type']} on unknown instance {instance_id}", result)
            return result
        raise
    instance = reservations[0]["Instances"][0]
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}

    if tags.get(OPT_IN_TAG, "").lower() != "true":
        result = {
            "status": "not_opted_in",
            "finding": finding,
            "recommendation": f"Isolate {instance_id} manually or tag it {OPT_IN_TAG}=true for automatic containment.",
            "currentSecurityGroups": [g["GroupId"] for g in instance.get("SecurityGroups", [])],
        }
        _notify(sns, f"[ACTION NEEDED] GuardDuty {finding['type']} on {instance_id}", result)
        return result

    volumes = [m["Ebs"]["VolumeId"] for m in instance.get("BlockDeviceMappings", []) if "Ebs" in m]
    plan = {
        "instanceId": instance_id,
        "vpcId": instance["VpcId"],
        "previousSecurityGroups": [g["GroupId"] for g in instance.get("SecurityGroups", [])],
        "volumesToSnapshot": volumes,
    }

    if is_dry_run():
        result = {"status": "dry_run", "finding": finding, "plan": plan}
        _notify(sns, f"[DRY RUN] Would isolate {instance_id}", result)
        return result

    now = datetime.now(UTC).isoformat(timespec="seconds")
    # Preserve evidence before changing anything.
    snapshot_ids = [
        ec2.create_snapshot(
            VolumeId=v,
            Description=f"Forensic snapshot for GuardDuty finding {finding['id']}",
            TagSpecifications=[{"ResourceType": "snapshot", "Tags": [
                {"Key": "SecurityFindingId", "Value": str(finding["id"])},
                {"Key": "SourceInstance", "Value": instance_id},
            ]}],
        )["SnapshotId"]
        for v in volumes
    ]

    group_id = quarantine_group(ec2, instance["VpcId"])
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[group_id])
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "SecurityQuarantine", "Value": str(finding["id"])},
            {"Key": "QuarantinedAt", "Value": now},
            {"Key": "PreviousSecurityGroups", "Value": ",".join(plan["previousSecurityGroups"])[:255]},
        ],
    )

    result = {"status": "isolated", "finding": finding, "plan": plan,
              "quarantineGroup": group_id, "snapshots": snapshot_ids, "isolatedAt": now}
    LOG.info(json.dumps(result))
    _notify(sns, f"[AUTO-CONTAINED] {instance_id} isolated after GuardDuty {finding['type']}", result)
    return result
