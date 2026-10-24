import os
import unittest
from unittest import mock

from fakes import FakeEC2, FakeSNS, load_handler

mod = load_handler("isolate_ec2")

IID = "i-0abc1234def567890"


def finding(severity=8.0, resource_type="Instance", instance_id=IID):
    return {
        "detail": {
            "id": "finding-1",
            "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "title": "EC2 instance is querying a domain associated with Bitcoin activity.",
            "severity": severity,
            "resource": {"resourceType": resource_type, "instanceDetails": {"instanceId": instance_id}},
        }
    }


def instance(opted_in=True):
    tags = [{"Key": "Name", "Value": "web"}] + ([{"Key": "AutoIsolate", "Value": "true"}] if opted_in else [])
    return {
        "InstanceId": IID,
        "VpcId": "vpc-1",
        "Tags": tags,
        "SecurityGroups": [{"GroupId": "sg-web"}, {"GroupId": "sg-ssh"}],
        "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-root"}}, {"Ebs": {"VolumeId": "vol-data"}}],
    }


@mock.patch.dict(os.environ, {"ALERT_TOPIC_ARN": "arn:aws:sns:us-east-2:111122223333:alerts",
                              "DRY_RUN": "false", "MIN_SEVERITY": "7"})
class Handler(unittest.TestCase):
    def test_opted_in_instance_is_snapshotted_then_isolated(self):
        ec2, sns = FakeEC2(instances={IID: instance()}), FakeSNS()
        result = mod.handler(finding(), ec2=ec2, sns=sns)

        self.assertEqual(result["status"], "isolated")
        self.assertEqual([c["VolumeId"] for c in ec2.called("create_snapshot")], ["vol-root", "vol-data"])
        self.assertEqual(ec2.called("modify_instance_attribute")[0]["Groups"], ["sg-quarantine-new"])
        # New quarantine group must have its default allow-all egress removed.
        self.assertEqual(len(ec2.called("revoke_security_group_egress")), 1)
        # Evidence is preserved before the network change.
        names = [c for c, _ in ec2.calls]
        self.assertLess(names.index("create_snapshot"), names.index("modify_instance_attribute"))
        tags = {t["Key"]: t["Value"] for t in ec2.called("create_tags")[0]["Tags"]}
        self.assertEqual(tags["PreviousSecurityGroups"], "sg-web,sg-ssh")
        self.assertEqual(len(sns.called("publish")), 1)

    def test_existing_quarantine_group_is_reused(self):
        ec2 = FakeEC2(instances={IID: instance()}, quarantine_exists=True)
        mod.handler(finding(), ec2=ec2, sns=FakeSNS())
        self.assertEqual(ec2.called("create_security_group"), [])
        self.assertEqual(ec2.called("modify_instance_attribute")[0]["Groups"], ["sg-quarantine-existing"])

    def test_instance_without_opt_in_tag_only_alerts(self):
        ec2, sns = FakeEC2(instances={IID: instance(opted_in=False)}), FakeSNS()
        result = mod.handler(finding(), ec2=ec2, sns=sns)
        self.assertEqual(result["status"], "not_opted_in")
        self.assertEqual(ec2.called("modify_instance_attribute"), [])
        self.assertEqual(ec2.called("create_snapshot"), [])
        self.assertEqual(len(sns.called("publish")), 1)

    def test_low_severity_is_skipped(self):
        ec2 = FakeEC2(instances={IID: instance()})
        self.assertEqual(mod.handler(finding(severity=5.0), ec2=ec2, sns=FakeSNS())["status"], "skipped")
        self.assertEqual(ec2.calls, [])

    def test_non_instance_finding_is_skipped(self):
        result = mod.handler(finding(resource_type="AccessKey"), ec2=FakeEC2(), sns=FakeSNS())
        self.assertEqual(result["status"], "skipped")

    def test_sample_finding_for_missing_instance_alerts(self):
        sns = FakeSNS()
        result = mod.handler(finding(instance_id="i-99999999"), ec2=FakeEC2(), sns=sns)
        self.assertEqual(result["status"], "not_found")
        self.assertEqual(len(sns.called("publish")), 1)

    def test_dry_run_changes_nothing(self):
        ec2 = FakeEC2(instances={IID: instance()})
        with mock.patch.dict(os.environ, {"DRY_RUN": "true"}):
            result = mod.handler(finding(), ec2=ec2, sns=FakeSNS())
        self.assertEqual(result["status"], "dry_run")
        self.assertEqual(result["plan"]["volumesToSnapshot"], ["vol-root", "vol-data"])
        self.assertEqual(ec2.called("create_snapshot"), [])
        self.assertEqual(ec2.called("modify_instance_attribute"), [])


if __name__ == "__main__":
    unittest.main()
