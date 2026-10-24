"""Re-apply S3 Block Public Access when someone weakens it on a bucket.

Trigger : EventBridge rule on the CloudTrail events PutBucketAcl, PutBucketPolicy,
          PutPublicAccessBlock and DeletePublicAccessBlock.
Action  : Turns on all four Block Public Access settings for the bucket, which
          neutralises public ACLs and public bucket policies, then alerts.
Opt-out : Buckets tagged AllowPublicAccess=true are left alone.
Safety  : DRY_RUN=true reports what would change without changing anything.

Defense in depth: the account-level public access block (threat-detection
module) already stops public exposure; this restores the bucket-level setting
too, so the bucket stays safe even if the account setting is ever relaxed.

MITRE ATT&CK: T1530 Data from Cloud Storage.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

EXEMPT_TAG = "AllowPublicAccess"
FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def is_dry_run() -> bool:
    return os.environ.get("DRY_RUN", "false").lower() == "true"


def bucket_from_event(event: dict[str, Any]) -> str | None:
    params = (event.get("detail") or {}).get("requestParameters") or {}
    return params.get("bucketName")


def error_code(exc: Exception) -> str:
    """botocore ClientError carries the AWS error code in exc.response."""
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def current_block(s3: Any, bucket: str) -> dict[str, bool]:
    try:
        return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except Exception as exc:  # noqa: BLE001 - narrowed by error code below
        if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return {}
        raise


def bucket_tags(s3: Any, bucket: str) -> dict[str, str]:
    try:
        tag_set = s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "NoSuchTagSet":
            return {}
        raise
    return {t["Key"]: t["Value"] for t in tag_set}


def missing_settings(config: dict[str, bool]) -> list[str]:
    return [k for k in FULL_BLOCK if not config.get(k, False)]


def _notify(sns: Any, subject: str, body: dict[str, Any]) -> None:
    topic = os.environ.get("ALERT_TOPIC_ARN")
    if topic:
        sns.publish(TopicArn=topic, Subject=subject[:100], Message=json.dumps(body, indent=2, default=str))


def handler(event: dict[str, Any], context: Any = None, s3: Any = None, sns: Any = None) -> dict[str, Any]:
    if s3 is None or sns is None:
        import boto3

        s3 = s3 or boto3.client("s3")
        sns = sns or boto3.client("sns")

    detail = event.get("detail") or {}
    bucket = bucket_from_event(event)
    if not bucket:
        return {"status": "skipped", "reason": "no bucket in event"}

    try:
        tags = bucket_tags(s3, bucket)
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "NoSuchBucket":
            return {"status": "skipped", "reason": "bucket no longer exists", "bucket": bucket}
        raise
    if tags.get(EXEMPT_TAG, "").lower() == "true":
        return {"status": "skipped", "reason": f"bucket tagged {EXEMPT_TAG}=true", "bucket": bucket}

    missing = missing_settings(current_block(s3, bucket))
    if not missing:
        return {"status": "compliant", "bucket": bucket}

    dry_run = is_dry_run()
    if not dry_run:
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=dict(FULL_BLOCK))

    result = {
        "status": "dry_run" if dry_run else "remediated",
        "action": "re-enable S3 Block Public Access",
        "bucket": bucket,
        "settingsRestored": missing,
        "actor": (detail.get("userIdentity") or {}).get("arn"),
        "sourceIp": detail.get("sourceIPAddress"),
        "eventName": detail.get("eventName"),
        "eventTime": detail.get("eventTime"),
        "remediatedAt": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    LOG.info(json.dumps(result))
    _notify(sns, f"[AUTO-REMEDIATED] Public access blocked on s3://{bucket}", result)
    return result
