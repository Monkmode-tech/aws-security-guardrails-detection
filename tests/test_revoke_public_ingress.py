import os
import unittest
from unittest import mock

from fakes import FakeEC2, FakeSNS, load_handler

mod = load_handler("revoke_public_ingress")

GROUP = "sg-0123456789abcdef0"


def event(group=GROUP, name="AuthorizeSecurityGroupIngress"):
    return {
        "detail": {
            "eventName": name,
            "eventTime": "2026-10-24T12:00:00Z",
            "sourceIPAddress": "203.0.113.10",
            "userIdentity": {"arn": "arn:aws:iam::111122223333:user/dev"},
            "requestParameters": {"groupId": group},
        }
    }


def rule(rule_id, cidr="0.0.0.0/0", proto="tcp", low=22, high=22, egress=False, v6=False):
    r = {"SecurityGroupRuleId": rule_id, "IsEgress": egress, "IpProtocol": proto, "FromPort": low, "ToPort": high}
    r["CidrIpv6" if v6 else "CidrIpv4"] = cidr
    return r


class RuleClassification(unittest.TestCase):
    ports = {22, 3389, 3306}

    def test_ssh_open_to_world_is_violation(self):
        self.assertTrue(mod.rule_is_violation(rule("r1"), self.ports))

    def test_ipv6_world_is_violation(self):
        self.assertTrue(mod.rule_is_violation(rule("r1", cidr="::/0", v6=True), self.ports))

    def test_all_traffic_to_world_is_violation(self):
        self.assertTrue(mod.rule_is_violation(rule("r1", proto="-1", low=-1, high=-1), self.ports))

    def test_port_range_covering_sensitive_port_is_violation(self):
        self.assertTrue(mod.rule_is_violation(rule("r1", low=3000, high=4000), self.ports))

    def test_https_to_world_is_allowed(self):
        self.assertFalse(mod.rule_is_violation(rule("r1", low=443, high=443), self.ports))

    def test_ssh_from_private_cidr_is_allowed(self):
        self.assertFalse(mod.rule_is_violation(rule("r1", cidr="10.0.0.0/8"), self.ports))

    def test_egress_is_ignored(self):
        self.assertFalse(mod.rule_is_violation(rule("r1", egress=True), self.ports))

    def test_icmp_is_ignored(self):
        self.assertFalse(mod.rule_is_violation(rule("r1", proto="icmp", low=-1, high=-1), self.ports))


class EventParsing(unittest.TestCase):
    def test_authorize_event(self):
        self.assertEqual(mod.group_id_from_event(event()), GROUP)

    def test_modify_rules_event(self):
        e = {"detail": {"requestParameters": {"ModifySecurityGroupRulesRequest": {"GroupId": GROUP}}}}
        self.assertEqual(mod.group_id_from_event(e), GROUP)

    def test_missing_group(self):
        self.assertIsNone(mod.group_id_from_event({"detail": {}}))


@mock.patch.dict(os.environ, {"ALERT_TOPIC_ARN": "arn:aws:sns:us-east-2:111122223333:alerts", "DRY_RUN": "false"})
class Handler(unittest.TestCase):
    def test_revokes_only_violating_rules_across_pages_and_alerts(self):
        ec2 = FakeEC2(
            groups={GROUP: {"GroupId": GROUP, "Tags": []}},
            rules=[rule("sgr-https", low=443, high=443), rule("sgr-ssh"), rule("sgr-rdp", low=3389, high=3389)],
        )
        sns = FakeSNS()
        result = mod.handler(event(), ec2=ec2, sns=sns)

        self.assertEqual(result["status"], "remediated")
        revoke = ec2.called("revoke_security_group_ingress")
        self.assertEqual(len(revoke), 1)
        self.assertEqual(revoke[0]["SecurityGroupRuleIds"], ["sgr-ssh", "sgr-rdp"])
        self.assertEqual(len(ec2.called("create_tags")), 1)
        self.assertEqual(len(sns.called("publish")), 1)
        self.assertLessEqual(len(sns.called("publish")[0]["Subject"]), 100)

    def test_compliant_group_is_untouched(self):
        ec2 = FakeEC2(groups={GROUP: {"GroupId": GROUP}}, rules=[rule("sgr-https", low=443, high=443)])
        sns = FakeSNS()
        self.assertEqual(mod.handler(event(), ec2=ec2, sns=sns)["status"], "compliant")
        self.assertEqual(ec2.called("revoke_security_group_ingress"), [])
        self.assertEqual(sns.called("publish"), [])

    def test_exempt_group_is_skipped(self):
        ec2 = FakeEC2(
            groups={GROUP: {"GroupId": GROUP, "Tags": [{"Key": "AllowPublicIngress", "Value": "true"}]}},
            rules=[rule("sgr-ssh")],
        )
        self.assertEqual(mod.handler(event(), ec2=ec2, sns=FakeSNS())["status"], "skipped")
        self.assertEqual(ec2.called("revoke_security_group_ingress"), [])

    def test_deleted_group_is_skipped(self):
        ec2 = FakeEC2(groups={})
        self.assertEqual(mod.handler(event(), ec2=ec2, sns=FakeSNS())["status"], "skipped")

    def test_dry_run_changes_nothing_but_still_alerts(self):
        ec2 = FakeEC2(groups={GROUP: {"GroupId": GROUP}}, rules=[rule("sgr-ssh")])
        sns = FakeSNS()
        with mock.patch.dict(os.environ, {"DRY_RUN": "true"}):
            result = mod.handler(event(), ec2=ec2, sns=sns)
        self.assertEqual(result["status"], "dry_run")
        self.assertEqual(ec2.called("revoke_security_group_ingress"), [])
        self.assertEqual(ec2.called("create_tags"), [])
        self.assertEqual(len(sns.called("publish")), 1)

    def test_custom_sensitive_ports(self):
        ec2 = FakeEC2(groups={GROUP: {"GroupId": GROUP}}, rules=[rule("sgr-8080", low=8080, high=8080)])
        with mock.patch.dict(os.environ, {"SENSITIVE_PORTS": "8080"}):
            result = mod.handler(event(), ec2=ec2, sns=FakeSNS())
        self.assertEqual(result["revokedRuleIds"], ["sgr-8080"])


if __name__ == "__main__":
    unittest.main()
