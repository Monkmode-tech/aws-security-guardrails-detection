"""In-memory stand-ins for the boto3 clients the Lambdas use.

They record every call so tests can assert exactly which AWS actions a handler
took - and, just as importantly, which it did not take.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

LAMBDAS = Path(__file__).resolve().parent.parent / "lambdas"


def load_handler(name: str):
    """Import lambdas/<name>/handler.py under a unique module name."""
    spec = importlib.util.spec_from_file_location(f"{name}_handler", LAMBDAS / name / "handler.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeClientError(Exception):
    """Mimics botocore.exceptions.ClientError's .response structure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def called(self, name: str) -> list[dict[str, Any]]:
        return [kwargs for call, kwargs in self.calls if call == name]


class FakeSNS(Recorder):
    def publish(self, **kwargs):
        self.calls.append(("publish", kwargs))
        return {"MessageId": "m-1"}


class FakeEC2(Recorder):
    def __init__(self, groups=None, rules=None, instances=None, quarantine_exists=False):
        super().__init__()
        self.groups = groups or {}
        self.rules = rules or []
        self.instances = instances or {}
        self.quarantine_exists = quarantine_exists

    # --- security groups ---
    def describe_security_groups(self, GroupIds=None, Filters=None):
        self.calls.append(("describe_security_groups", {"GroupIds": GroupIds, "Filters": Filters}))
        if GroupIds:
            return {"SecurityGroups": [self.groups[g] for g in GroupIds if g in self.groups]}
        if self.quarantine_exists:
            return {"SecurityGroups": [{"GroupId": "sg-quarantine-existing"}]}
        return {"SecurityGroups": []}

    def describe_security_group_rules(self, **kwargs):
        self.calls.append(("describe_security_group_rules", kwargs))
        # Return the rules in two pages to exercise pagination.
        if "NextToken" not in kwargs:
            return {"SecurityGroupRules": self.rules[:1], "NextToken": "page-2" if len(self.rules) > 1 else None}
        return {"SecurityGroupRules": self.rules[1:]}

    def revoke_security_group_ingress(self, **kwargs):
        self.calls.append(("revoke_security_group_ingress", kwargs))

    def revoke_security_group_egress(self, **kwargs):
        self.calls.append(("revoke_security_group_egress", kwargs))

    def create_security_group(self, **kwargs):
        self.calls.append(("create_security_group", kwargs))
        return {"GroupId": "sg-quarantine-new"}

    def create_tags(self, **kwargs):
        self.calls.append(("create_tags", kwargs))

    # --- instances ---
    def describe_instances(self, InstanceIds):
        self.calls.append(("describe_instances", {"InstanceIds": InstanceIds}))
        iid = InstanceIds[0]
        if iid not in self.instances:
            raise FakeClientError("InvalidInstanceID.NotFound")
        return {"Reservations": [{"Instances": [self.instances[iid]]}]}

    def create_snapshot(self, **kwargs):
        self.calls.append(("create_snapshot", kwargs))
        return {"SnapshotId": f"snap-{kwargs['VolumeId']}"}

    def modify_instance_attribute(self, **kwargs):
        self.calls.append(("modify_instance_attribute", kwargs))


class FakeS3(Recorder):
    def __init__(self, block=None, tags=None, exists=True):
        super().__init__()
        self.block = block  # None = no configuration
        self.tags = tags  # None = no tag set
        self.exists = exists

    def get_bucket_tagging(self, Bucket):
        self.calls.append(("get_bucket_tagging", {"Bucket": Bucket}))
        if not self.exists:
            raise FakeClientError("NoSuchBucket")
        if self.tags is None:
            raise FakeClientError("NoSuchTagSet")
        return {"TagSet": [{"Key": k, "Value": v} for k, v in self.tags.items()]}

    def get_public_access_block(self, Bucket):
        self.calls.append(("get_public_access_block", {"Bucket": Bucket}))
        if self.block is None:
            raise FakeClientError("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": self.block}

    def put_public_access_block(self, **kwargs):
        self.calls.append(("put_public_access_block", kwargs))
